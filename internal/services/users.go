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
type UserService struct{ db *gorm.DB }

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
	if u.Password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil
}

func (s *UserService) Create(ctx context.Context, username, password, email, name string) (*storage.User, error) {
	if username == "" || password == "" {
		return nil, errors.New("username/password required")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	u := &storage.User{Username: username, Password: string(hash), Email: email, EmailVerified: false, Name: name}
	if err := s.db.WithContext(ctx).Create(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserService) List(ctx context.Context, limit int) ([]storage.User, error) {
	if limit <= 0 {
		limit = 100
	}
	var users []storage.User
	if err := s.db.WithContext(ctx).Limit(limit).Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (s *UserService) IDPtr(id uint64) *uint64 { return &id }

// Save 持久化用户字段变更。
func (s *UserService) Save(ctx context.Context, u *storage.User) error {
	return s.db.WithContext(ctx).Save(u).Error
}

// UpdateProfile 更新当前用户的基本资料（姓名与邮箱）。
func (s *UserService) UpdateProfile(ctx context.Context, id uint64, name, email string) (*storage.User, error) {
	u, err := s.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if name != "" {
		u.Name = name
	}
	if email != "" {
		u.Email = email
	}
	if err := s.Save(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// ChangePassword 变更用户口令（需要提供旧口令）。
func (s *UserService) ChangePassword(ctx context.Context, id uint64, oldPwd, newPwd string) error {
	u, err := s.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if !s.CheckPassword(u, oldPwd) {
		return errors.New("bad_password")
	}
	if len(newPwd) < 6 {
		return errors.New("weak_password")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(newPwd), bcrypt.DefaultCost)
	u.Password = string(hash)
	return s.Save(ctx, u)
}

// SetPassword 由管理员直接设置用户口令（无需旧口令）。
func (s *UserService) SetPassword(ctx context.Context, id uint64, newPwd string) error {
	if len(newPwd) < 6 {
		return errors.New("weak_password")
	}
	u, err := s.FindByID(ctx, id)
	if err != nil {
		return err
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(newPwd), bcrypt.DefaultCost)
	u.Password = string(hash)
	return s.Save(ctx, u)
}

// SetDevRole 设置/取消开发者角色。
func (s *UserService) SetDevRole(ctx context.Context, id uint64, isDev bool) error {
	u, err := s.FindByID(ctx, id)
	if err != nil {
		return err
	}
	u.IsDev = isDev
	return s.Save(ctx, u)
}
