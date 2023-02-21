package sqlstore_test

import (
	"github.com/konstantinMosin93/httpRestApi/internal/app/model"
	"github.com/konstantinMosin93/httpRestApi/internal/app/store"
	"github.com/konstantinMosin93/httpRestApi/internal/app/store/sqlstore"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUserRepository_Create(t *testing.T) {
	db, teardown := sqlstore.TestDB(t, databaseURL)
	defer teardown("users")

	st := sqlstore.New(db)
	u := model.TestUser(t)
	assert.NoError(t, st.User().Create(u))
	assert.NotNil(t, u)
}

func TestUserRepository_FindByEmail(t *testing.T) {
	db, teardown := sqlstore.TestDB(t, databaseURL)
	defer teardown("users")

	st := sqlstore.New(db)
	email := "user@example.org"
	_, err := st.User().FindByEmail(email)
	assert.EqualError(t, err, store.ErrRecordNotFound.Error())

	u1 := model.TestUser(t)
	_ = st.User().Create(u1)

	u2, err := st.User().FindByEmail(u1.Email)
	assert.NoError(t, err)
	assert.NotNil(t, u2)
}

func TestUserRepository_Find(t *testing.T) {
	db, teardown := sqlstore.TestDB(t, databaseURL)
	defer teardown("users")

	st := sqlstore.New(db)
	_, err := st.User().Find(1)
	assert.EqualError(t, err, store.ErrRecordNotFound.Error())

	u1 := model.TestUser(t)
	_ = st.User().Create(u1)

	u2, err := st.User().Find(u1.ID)
	assert.NoError(t, err)
	assert.NotNil(t, u2)
}
