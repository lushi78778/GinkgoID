export async function confirm(options: { title?: string; content?: string; okText?: string; cancelText?: string }): Promise<boolean> {
  const { title, content } = options
  const msg = [title, content].filter(Boolean).join('\n') || '确认操作？'
  return Promise.resolve(window.confirm(msg))
}
