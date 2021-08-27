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
		ok, err := e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(r), "*")
		assert.Equal(t, true, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Should Map a User with Group", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()
		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(r), "*")
		ok, err := e.AddRoleForUser(utils.CreateUrn(u), utils.CreateUrn(g))
		assert.Equal(t, true, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return false if group doesnt have resource permission", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		e.AddPolicy("", "", "*")
		ok, err := e.Enforce(utils.CreateUrn(g), utils.CreateUrn(r), "*")
		assert.Equal(t, false, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Check if group has resource permission", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(r), "*")
		ok, err := e.Enforce(utils.CreateUrn(g), utils.CreateUrn(r), "*")
		assert.Equal(t, true, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return false if user doesnt belong to resource group", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()

		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(r), "*")

		ok, err := e.Enforce(utils.CreateUrn(u), utils.CreateUrn(r), "*")
		assert.Equal(t, false, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return true if user belong to resource group", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()

		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(r), "*")
		e.AddRoleForUser(utils.CreateUrn(u), utils.CreateUrn(g))

		ok, err := e.Enforce(utils.CreateUrn(u), utils.CreateUrn(r), "*")
		assert.Equal(t, true, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Should Create a Policy With Project", func(t *testing.T) {
		p := utils.NewProject()
		g := utils.NewGroup()
		r := utils.NewResource()
		ok, err := e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(p, r), "*")
		assert.Equal(t, true, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return true if user belong to resource group with policy", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()
		p := utils.NewProject()

		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(p, r), "*")
		e.AddRoleForUser(utils.CreateUrn(u), utils.CreateUrn(g))

		ok, err := e.Enforce(utils.CreateUrn(u), utils.CreateUrn(p, r), "*")
		assert.Equal(t, true, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return true if user has access to parent policy", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()
		p := utils.NewProject()

		w := utils.NewWildCard(r)
		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(p, w), "*")
		e.AddRoleForUser(utils.CreateUrn(u), utils.CreateUrn(g))

		ok, err := e.Enforce(utils.CreateUrn(u), utils.CreateUrn(p, r), "*")
		assert.Equal(t, true, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return true if user has access to all projects", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()
		p := utils.NewProject()

		w := utils.NewWildCard(p)
		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(w), "*")
		e.AddRoleForUser(utils.CreateUrn(u), utils.CreateUrn(g))

		ok, err := e.Enforce(utils.CreateUrn(u), utils.CreateUrn(p, r), "*")
		assert.Equal(t, true, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return true if user is assigned to role with access", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()
		p := utils.NewProject()
		role := utils.NewRole()

		action := "read"

		w := utils.NewWildCard(p)
		e.AddNamedGroupingPolicy("g2", action, utils.CreateUrn(role))
		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(w), utils.CreateUrn(role))
		e.AddRoleForUser(utils.CreateUrn(u), utils.CreateUrn(g))

		ok, err := e.Enforce(utils.CreateUrn(u), utils.CreateUrn(p, r), action)
		assert.Equal(t, true, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return false if user is assigned to role without access", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()
		p := utils.NewProject()
		role1 := utils.NewRole()
		role2 := utils.NewRole()

		action := "read"

		w := utils.NewWildCard(p)
		e.AddNamedGroupingPolicy("g2", action, utils.CreateUrn(role1))
		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(w), utils.CreateUrn(role2))
		e.AddRoleForUser(utils.CreateUrn(u), utils.CreateUrn(g))

		ok, err := e.Enforce(utils.CreateUrn(u), utils.CreateUrn(p, r), action)
		assert.Equal(t, false, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

	t.Run("Return false if user role action doest match", func(t *testing.T) {
		g := utils.NewGroup()
		r := utils.NewResource()
		u := utils.NewUser()
		p := utils.NewProject()
		role := utils.NewRole()

		action := "read"

		w := utils.NewWildCard(p)
		e.AddNamedGroupingPolicy("g2", action, utils.CreateUrn(role))
		e.AddPolicy(utils.CreateUrn(g), utils.CreateUrn(w), utils.CreateUrn(role))
		e.AddRoleForUser(utils.CreateUrn(u), utils.CreateUrn(g))

		ok, err := e.Enforce(utils.CreateUrn(u), utils.CreateUrn(p, r), "write")
		assert.Equal(t, false, ok)
		assert.NoError(t, err)
		e.ClearPolicy()
	})

}
