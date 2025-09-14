package services

// 用户服务：提供基础的用户查询、创建与口令校验能力。

import (
    "context"
    "errors"

    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"

    "ginkgoid/internal/storage"
)

// UserService 提供基础用户 CRUD 与口令校验。
type UserService struct { db *gorm.DB }

func NewUserService(db *gorm.DB) *UserService { return &UserService{db: db} }

func (s *UserService) FindByUsername(ctx context.Context, username string) (*storage.User, error) {
    var u storage.User
    if err := s.db.WithContext(ctx).Where("username = ?", username).First(&u).Error; err != nil {
        return nil, err
    }
    return &u, nil
}

func (s *UserService) FindByID(ctx context.Context, id uint64) (*storage.User, error) {
    var u storage.User
    if err := s.db.WithContext(ctx).Where("id = ?", id).First(&u).Error; err != nil {
        return nil, err
    }
    return &u, nil
}

// CheckPassword 校验用户口令（bcrypt）。
func (s *UserService) CheckPassword(u *storage.User, password string) bool {
    if u.Password == "" { return false }
    return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil
}

func (s *UserService) Create(ctx context.Context, username, password, email, name string) (*storage.User, error) {
    if username == "" || password == "" {
        return nil, errors.New("username/password required")
    }
    hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    u := &storage.User{Username: username, Password: string(hash), Email: email, EmailVerified: false, Name: name}
    if err := s.db.WithContext(ctx).Create(u).Error; err != nil { return nil, err }
    return u, nil
}

func (s *UserService) List(ctx context.Context, limit int) ([]storage.User, error) {
    if limit <= 0 { limit = 100 }
    var users []storage.User
    if err := s.db.WithContext(ctx).Limit(limit).Find(&users).Error; err != nil { return nil, err }
    return users, nil
}

func (s *UserService) IDPtr(id uint64) *uint64 { return &id }
