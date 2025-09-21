// Package services 提供应用的领域服务层，封装跨存储的聚合逻辑。
// 该层对 handlers 提供较为稳定的接口，避免在 HTTP 层直接操作数据访问或缓存细节。
package services
