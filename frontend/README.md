# GinkgoID Console — Next.js 前端说明

这一部分是 GinkgoID 的用户/开发者/管理员控制台，使用 Next.js 14 App Router + Tailwind 构建，最终以静态导出方式交付给 Go 服务托管。下面是日常开发、构建与扩展时需要掌握的细节。

- [技术栈与目标](#技术栈与目标)
- [快速启动](#快速启动)
- [构建与发布流水线](#构建与发布流水线)
- [目录结构与职责](#目录结构与职责)
- [全局 Provider 与布局](#全局-provider-与布局)
- [数据访问与鉴权](#数据访问与鉴权)
- [样式体系](#样式体系)
- [常用组件与表单规范](#常用组件与表单规范)
- [角色导航与路由约定](#角色导航与路由约定)
- [质量保障与调试](#质量保障与调试)
- [与后端集成注意事项](#与后端集成注意事项)
- [添加新页面的套路](#添加新页面的套路)

## 技术栈与目标

- Next.js 14 App Router，`output: 'export'` —— 构建后生成完全静态的 `out/` 目录，交由 Go 服务托管。
- UI：Tailwind CSS + 一组自维护的 UI wrapper (`components/ui/*`)，结合 Radix UI 组件（Dialog / Switch 等）。
- 状态层：客户端 Hooks + React Context，`useAuth` 管理登陆态与用户信息。
- 校验与表单：React Hook Form 搭配 Zod，Sonner 负责通知弹窗。
- 目标：三个角色（用户 / 开发者 / 管理员）共用一套控制台，在 SPA 内完成资料管理、应用管理、审计等任务。

## 快速启动

```bash
cd frontend
npm install            # 或者 pnpm install / yarn install
npm run dev            # 默认监听 http://127.0.0.1:3000
```

开发模式下会代理 API 到同域（仍需后端在 8080 或配置的端口运行，且浏览器 cookie 指向后端域名）。由于使用静态导出，部分仅服务器端可用的能力（如 API routes）不可用。

常用脚本（`package.json`）：

- `npm run dev`：开发服务器（HMR）。
- `npm run build`：Tailwind 预构建 + `next build`（输出 `out/`）。
- `npm run postbuild`：将 `out/` 拷贝到仓库根目录的 `web/app`，供 Go 服务使用。
- `npm run start`：如需单独以 Node 方式预览（`next start`）。
- `npm run lint`：调用 `next lint`。

## 构建与发布流水线

1. `npm run build` 会先执行 `tailwindcss -i ./globals.css -o ./public/app.css`，把 Tailwind 输出到 `public/app.css`（用于服务端登录模板也能共享主题变量）。
2. 同一个命令随后运行 `next build`，由于 `next.config.mjs` 声明 `output: 'export'`，Next.js 会在 `.next` 基础上生成 `out/` 静态文件。
3. `npm run postbuild` 负责把 `out/` 整体复制到项目根目录的 `web/app`。`cmd/server` 在运行时会查找该目录并通过 Gin 静态托管 `/`、`/_next`、`/assets` 等路径。


## 目录结构与职责

| 路径 | 描述 |
| ---- | ---- |
| `app/` | Next.js App Router 页面。每个子目录即一个路由，`page.tsx` 为入口组件。 |
| `app/layout.tsx` | 应用级布局，注入 Providers、全局样式。`metadata` 定义默认 `<head>` 信息。 |
| `components/providers.tsx` | 包装全局 Provider，加载主题、AuthProvider、侧边栏布局。 |
| `components/layout/SidebarLayout.tsx` | 控制台主框架，包含导航、顶栏、主题切换、登录/退出按钮。 |
| `components/ui/` | 轻量 UI 组件封装（Button、Card、Dialog、Table 等），统一样式。 |
| `lib/` | 公共工具：`auth.tsx`、`api.ts`、`theme.ts`、`pkce.ts` 等。 |
| `globals.css` | Tailwind 输入文件，定义 CSS 变量、基础样式。 |
| `public/app.css` | 构建时生成的 Tailwind 输出，`providers.tsx` 会动态注入 `<link href="/app.css">`。 |
| `next.config.mjs` | Next.js 配置，开启静态导出、禁用默认 Image 优化等。 |

## 全局 Provider 与布局

- `Providers` (components/providers.tsx) 在客户端加载：
  - 调用 `initTheme()` 设置主题并挂载 `public/app.css`。
  - 注入 `AuthProvider`（见下一节）以及 `SidebarLayout`。
  - 渲染 `sonner` 的 `Toaster`。
- `SidebarLayout` 根据 `useAuth()` 返回的角色字段（`is_admin` / `is_dev`）过滤导航项。导航定义集中于 `navItems` 数组，新增页面时记得在这里维护。
- 顶部工具条提供主题切换、当前用户名、退出登录入口。退出时调用 `/logout` 并重定向回当前页。

## 数据访问与鉴权

### AuthProvider

文件：[`lib/auth.tsx`](lib/auth.tsx)

- 首次挂载时调用 `/api/me` 获取当前用户信息（cookie 必须同域）。
- `me` 为 `null` 时视为未登录，`loading` 控制页面骨架加载。
- `useAuth()` 返回 `me`、`loading`、`refresh()`、`logout()` 四个字段，页面侧边导航与按钮需要使用它判断角色。

### API Helper

文件：[`lib/api.ts`](lib/api.ts)

- 默认携带 `credentials: 'include'`，确保 Cookie 在同域下发送。
- 遇到 `401` 时直接跳转 `/login?next=当前路径`。Go 服务负责渲染登录页并在完成后带着 `next` 回 SPA。
- `apiJSON()` 是 JSON POST 封装。
- 页面请求中建议统一使用 `api()`，便于后续插入全局错误处理或重试逻辑。

### 与后端的约定

- 控制台依赖下列 REST 接口：`/api/me`、`/api/consents`、`/api/clients`、`/api/logs` 等（具体请参考 Go 端 handler）。
- 所有请求需在同域，通过 Cookie 会话授权；无需单独的 OAuth token。
- 若接口尚未实现，页面通常会展示 Toast 错误并提示“可能尚未实现后端接口”，确保体验友好。

## 样式体系

- Tailwind CSS 配置在 [`tailwind.config.js`](tailwind.config.js)，颜色全部绑定到 CSS 变量，支持主题切换。
- `globals.css` 定义基础变量与 `.card`、`.btn` 等通用样式；`@layer base` 覆盖全局背景/字体颜色。
- 构建时 Tailwind 输出写入 `public/app.css`，运行时 `Providers` 动态挂载 `<link>`，保证静态导出的 HTML 也能获取最新样式。
- 主题切换：`lib/theme.ts` 负责保存与读取 `localStorage` 中的主题枚举（light/dark/system），并根据系统偏好监听实时更新。

## 常用组件与表单规范

- `components/ui` 集合了按钮、表单输入、Card 等基础组件，统一封装 Tailwind class 与交互状态。
- 表单：
  - 使用 React Hook Form + Zod。`app/profile/page.tsx` 是完整示例：一个表单两个 schema（基础信息 + 修改密码）。
  - 错误信息通过 Zod 提供中文提示，结合 Sonner 进行用户反馈。
  - 复选、开关类组件使用 Radix UI + Tailwind 封装，位于 `components/ui/switch.tsx` 等文件。
- 表格：`components/ui/data-table.tsx` 基于 `@tanstack/react-table`，后续扩展可直接引用。
- Icon：当前依赖 `lucide-react`。需要新图标时直接 `import { IconName } from 'lucide-react'`。

## 角色导航与路由约定

- 所有页面默认放在 `app/` 下。示例：
  - `/` -> `app/page.tsx`
  - `/profile` -> `app/profile/page.tsx`
  - `/admin/dashboard` -> `app/admin/dashboard/page.tsx`
- `SidebarLayout` 中的 `navItems` 控制导航展示；`dev: true` 表示仅开发者或管理员可见，`admin: true` 表示仅管理员可见。
- 需要在构建期导出的页面必须在 `app/` 下有 `page.tsx`。若页面需要共享布局，可添加 `layout.tsx`。
- 静态导出要求所有路由可在构建期枚举。动态数据仍在运行时通过 API 拉取，不影响。

## 质量保障与调试

- Lint：`npm run lint` 使用 `next lint`（内部 ESLint + TypeScript 插件）。
- TypeScript：严格模式开启，尽量避免 `any`；必要时通过类型守卫。
- 单元测试尚未接入。若补齐测试，可选 Vitest / Playwright，再在脚本里串联。
- 浏览器控制台调试：接口错误统一抛出 `Error`，同时触发 Sonner Toast，方便定位。
- 构建调试：`npm run build` 失败时多半是未静态可导出的路径（例如使用了 `headers()`、`draftMode()` 等运行时 API），控制台会报错提示。

## 与后端集成注意事项

- 所有相对路径（`/api/...`、`/logout`）都假设控制台与 Go 服务共域部署。如果拆分域名，需要自行引入代理或调整 `fetch` 请求。
- 静态资源部署在 `web/app` 下，Go 服务会根据请求路径映射到 `_next`、`assets` 等目录。确保 `npm run postbuild` 后将这些文件提交或打包进镜像。
- 登录页仍由后端模板 `web/templates/login.html` 渲染；控制台通过 `useAuth()` 与 `/login?next=` 协议联动。
- 若要新增 API：先在 Go 端实现 `/api/...`，添加 Swagger 注释，再在前端调用 `api()`。

## 添加新页面

1. 在 `app/` 目录创建子目录，例如 `app/clients/audit/page.tsx`。
2. 在页面组件内引入 `useAuth()`，根据角色做访问控制；必要时显示未授权提示。
3. 数据请求使用 `api()`；若需要表单，搭配 React Hook Form + Zod，参考 `profile` 页面。
4. 在 `components/layout/SidebarLayout.tsx` 的 `navItems` 中添加导航项，并标记 `dev/admin` 权限。
5. 开发调试完成后运行 `npm run build && npm run postbuild`，确认 Go 服务能正确加载静态文件。

---

控制台仍在迭代中，遇到 UI/UX 问题随时在仓库开 Issue，或直接提交 PR。
