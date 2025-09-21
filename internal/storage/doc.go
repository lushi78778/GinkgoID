// Package storage 提供底层持久化与缓存适配，实现数据库连接、自动迁移以及 GORM 模型声明。
// 其它层应通过 services 间接访问存储，以便集中处理事务与指标。
package storage
