// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"errors"
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	luafilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/xds/types"
)

func init() {
	registerHTTPFilter(&lua{})
}

type lua struct{}

var _ httpFilter = &lua{}

// patchHCM builds and appends a single Lua filter to the HTTP Connection Manager
// if any route in the listener has Lua configuration. The filter uses LuaPerRoute
// for per-route configuration (https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/lua/v3/lua.proto#envoy-v3-api-msg-extensions-filters-http-lua-v3-luaperroute).
func (*lua) patchHCM(mgr *hcmv3.HttpConnectionManager, irListener *ir.HTTPListener) error {
	if mgr == nil {
		return errors.New("hcm is nil")
	}
	if irListener == nil {
		return errors.New("ir listener is nil")
	}

	// Check if any route has Lua configuration
	hasLua := false
	for _, route := range irListener.Routes {
		if route != nil && route.EnvoyExtensions != nil && route.EnvoyExtensions.Lua != nil {
			hasLua = true
			break
		}
	}

	if !hasLua {
		return nil
	}

	// Create a single Lua filter if it doesn't already exist
	filterName := egv1a1.EnvoyFilterLua.String()
	if hcmContainsFilter(mgr, filterName) {
		return nil
	}

	// Create an empty Lua filter - actual Lua code will be configured per-route via LuaPerRoute
	luaProto := &luafilterv3.Lua{}
	if err := luaProto.ValidateAll(); err != nil {
		return err
	}

	luaAny, err := anypb.New(luaProto)
	if err != nil {
		return err
	}

	mgr.HttpFilters = append(mgr.HttpFilters, &hcmv3.HttpFilter{
		Name: filterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: luaAny,
		},
	})

	return nil
}

// patchResources patches the cluster resources for the http lua code source.
func (*lua) patchResources(_ *types.ResourceVersionTable, _ []*ir.HTTPRoute) error {
	return nil
}

// patchRoute patches the provided route with LuaPerRoute configuration if applicable.
// buildLuas combines all Lua scripts from a policy into a single ir.Lua.
func (*lua) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute, _ *ir.HTTPListener) error {
	if route == nil {
		return errors.New("xds route is nil")
	}
	if irRoute == nil {
		return errors.New("ir route is nil")
	}
	if irRoute.EnvoyExtensions == nil || irRoute.EnvoyExtensions.Lua == nil {
		return nil
	}

	filterName := egv1a1.EnvoyFilterLua.String()
	filterCfg := route.GetTypedPerFilterConfig()
	if _, ok := filterCfg[filterName]; ok {
		// This should not happen since this is the only place where the Lua
		// filter config is added in a route.
		return fmt.Errorf("route already contains lua config: %+v", route)
	}

	// Use the combined Lua script
	luaScript := irRoute.EnvoyExtensions.Lua.Code
	if luaScript == nil {
		return fmt.Errorf("lua script code is nil for route %s", irRoute.Name)
	}

	// Create LuaPerRoute configuration with the combined script
	luaPerRoute := &luafilterv3.LuaPerRoute{
		Override: &luafilterv3.LuaPerRoute_SourceCode{
			SourceCode: &corev3.DataSource{
				Specifier: &corev3.DataSource_InlineString{
					InlineString: *luaScript,
				},
			},
		},
	}

	if err := luaPerRoute.ValidateAll(); err != nil {
		return fmt.Errorf("failed to validate LuaPerRoute config: %w", err)
	}

	luaPerRouteAny, err := anypb.New(luaPerRoute)
	if err != nil {
		return fmt.Errorf("failed to marshal LuaPerRoute config: %w", err)
	}

	if filterCfg == nil {
		route.TypedPerFilterConfig = make(map[string]*anypb.Any)
	}

	route.TypedPerFilterConfig[filterName] = luaPerRouteAny

	return nil
}
