<?php

namespace Spatie\Permission;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Collection;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Auth\Access\Authorizable;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;

class PermissionRegistrar
{
    /** @var \Illuminate\Contracts\Auth\Access\Gate */
    protected $gate;

    /** @var \Illuminate\Contracts\Cache\Repository */
    protected $cache;

    /** @var string */
    protected $cacheKey = 'spatie.permission.cache';
    
    private $permissions;
    private $permissions_plucked = [];
    public $users_permissions = [];

    public function __construct(Gate $gate, Repository $cache)
    {
        $this->gate = $gate;
        $this->cache = $cache;

        $hasDBConnection = true;
        try {
            DB::connection()->getPdo();
        } catch (\Exception $e) {
            $hasDBConnection = false;
        }

        if($hasDBConnection){
            $this->getPermissions();
            $this->setPermissionsGroupBy();
        }
    }

    public function registerPermissions(): bool
    {
        $this->gate->before(function (Authorizable $user, string $ability) {
            try {
                if (method_exists($user, 'hasPermissionTo')) {
                    $rez = $user->hasPermissionTo($ability) ?: null;
                    return $rez;
                }
            } catch (PermissionDoesNotExist $e) {
            }
        });

        return true;
    }

    public function forgetCachedPermissions()
    {

        if($this->permissions) {
            $grouped = $this->permissions->groupBy('permissionable_type');
            foreach($grouped as $key => $group) {
                $cache_key = "permissions_".mb_strtolower(str_replace("\\", "_", $key));
                $this->cache->forget($cache_key);
            }
        }
        $this->cache->forget($this->cacheKey . "_plucked");
        $this->cache->forget($this->cacheKey);

        $this->permissions = null;
        $this->permissions_plucked = [];
        $this->users_permissions = [];
    }

    public function getPermissions(): Collection
    {

        if (!$this->permissions) {
            $this->permissions = $this->cache->remember($this->cacheKey, config('permission.cache_expiration_time'), function () {
                $permission_namespace = config('permission.models.permission');
                return app($permission_namespace)->with('roles')->get();
            });
        }

        if (!$this->permissions_plucked) {
            $this->permissions_plucked = $this->cache->remember($this->cacheKey . "_plucked", config('permission.cache_expiration_time'), function () {
                return $this->permissions->pluck('id', 'name')->toArray();
            });
        }

//        $grouped = $this->permissions->groupBy('permissionable_type');
//        foreach($grouped as $key => $group){
//            $cache_key = "permissions_".mb_strtolower(str_replace("\\", "_", $key));
//            $this->cache->remember($cache_key, config('permission.cache_expiration_time'), function () use ($group) {
//                return $group->pluck('id', 'name')->toArray();
//            });
//        }

        return $this->permissions;
    }
    
    public function getPermissionID($name){
        $id = null;
        if ($this->permissions_plucked || count($this->permissions_plucked) == 0) {
            $this->getPermissions();
        }
        $id = $this->permissions_plucked[$name];
        return $id;
    }

    public function setPermissionsGroupBy()
    {
        $grouped = $this->permissions->groupBy('permissionable_type');

        foreach($grouped as $key => $group){
            $cache_key = "permissions_".mb_strtolower(str_replace("\\", "_", $key));
            $this->cache->remember($cache_key, config('permission.cache_expiration_time'), function () use ($group) {
                return $group->pluck('id', 'name')->toArray();
            });

            foreach (['create', 'read', 'edit', 'delete'] as $action){
                $this->cache->remember($cache_key.$action, config('permission.cache_expiration_time'), function () use ($group, $action) {
                    $filtered = $group->filter(function ($value, $key) use ($action) {
                        return $value->action == $action;
                    });
                    return $filtered->pluck('id', 'name')->toArray();
                });
            }

        }
    }

    public function getPermissionsByNamespace($namespace, $action = ""){

        $namespace_cache_key = "permissions_".mb_strtolower(str_replace("\\", "_", $namespace)) . $action;
        if($this->cache->has($namespace_cache_key)){
            return $this->cache->get($namespace_cache_key);
        }
        $this->setPermissionsGroupBy($namespace);

        return $this->cache->get($namespace_cache_key);
    }

    public function getPermissionsByUserID($id)
    {
        $all_user_permissions = [];
        if(app('auth')->user()) {
            if(array_key_exists($id, $this->users_permissions)){
                $all_user_permissions = $this->users_permissions[$id];
            } else {
                $all_user_permissions = app('auth')->user()->getAllPermissionsIDs();
                $this->users_permissions[$id] = $all_user_permissions;
            }
        }
        return $all_user_permissions;
    }

}
