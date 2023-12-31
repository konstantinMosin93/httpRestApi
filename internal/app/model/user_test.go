package model_test

import (
	model2 "github.com/konstantinMosin93/httpRestApi/internal/app/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUser_BeforeCreate(t *testing.T) {
	u := model2.TestUser(t)
	assert.NoError(t, u.BeforeCreate())
	assert.NotEmpty(t, u.EncryptedPassword)
}

func TestUser_Validate(t *testing.T) {
	testCases := []struct {
		name    string
		u       func() *model2.User
		isValid bool
	}{
		{
			name: "valid",
			u: func() *model2.User {
				return model2.TestUser(t)
			},
			isValid: true,
		},
		{
			name: "encrypted password",
			u: func() *model2.User {
				u := model2.TestUser(t)
				u.Password = ""
				u.EncryptedPassword = "encrypted_password"
				return u
			},
			isValid: true,
		},
		{
			name: "empty email",
			u: func() *model2.User {
				u := model2.TestUser(t)
				u.Email = ""
				return u
			},
			isValid: false,
		},
		{
			name: "invalid email",
			u: func() *model2.User {
				u := model2.TestUser(t)
				u.Email = "invalid"
				return u
			},
			isValid: false,
		},
		{
			name: "empty password",
			u: func() *model2.User {
				u := model2.TestUser(t)
				u.Password = ""
				return u
			},
			isValid: false,
		},
		{
			name: "short password",
			u: func() *model2.User {
				u := model2.TestUser(t)
				u.Password = "short"
				return u
			},
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.isValid {
				assert.NoError(t, tc.u().Validate())
			} else {
				assert.Error(t, tc.u().Validate())
			}
		})
	}
}
