package main

import (
	"testing"

	"github.com/rsbh/auth/utils"
	"github.com/stretchr/testify/assert"
)

func TestRules(t *testing.T) {
	e := utils.NewEnforcer("config/model.conf", "config/policy.csv")

	t.Run("Should Create a Policy", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		ok, err := e.AddPolicy(g.GetId(), r.GetId(), "*", "*")
		assert.Equal(t, ok, true)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Should Create a Policy With Project", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		p := utils.NewProject()
		ok, err := e.AddPolicy(g.GetId(), r.GetId(), p.GetId(), "*")
		assert.Equal(t, ok, true)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Should Map a User with Group", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()
		p := utils.NewProject()
		e.AddPolicy(g.GetId(), r.GetId(), p.GetId(), "*")
		ok, err := e.AddRoleForUserInDomain(u.GetId(), g.GetId(), p.GetId())
		assert.Equal(t, ok, true)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return false if group doesnt have resource permission", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		p := utils.NewProject()
		e.AddPolicy("", "", "", "*")
		ok, err := e.Enforce(g.GetId(), r.GetId(), p.GetId(), "*")
		assert.Equal(t, ok, false)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Check if group has resource permission", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		p := utils.NewProject()
		e.AddPolicy(g.GetId(), r.GetId(), p.GetId(), "*")
		ok, err := e.Enforce(g.GetId(), r.GetId(), p.GetId(), "*")
		assert.Equal(t, ok, true)
		assert.NoError(t, err)
		e.ClearPolicy()
	})
}
