// Package config 负责加载与解析进程配置，支持 YAML/JSON 配置文件与默认值合并。
// 该层保持无外部依赖，供 main 与其它组件直接读取结构化配置。
package config
