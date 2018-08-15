<?php

namespace Spatie\Permission;

use Illuminate\Support\Collection;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Cache\Repository;
use Spatie\Permission\Contracts\Permission;
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
    }

    public function registerPermissions(): bool
    {
        $this->gate->before(function (Authorizable $user, string $ability) {
            try {
                if (method_exists($user, 'hasPermissionTo')) {
                    start_measure('registerPermissions-hasPermissionTo');
                    $rez = $user->hasPermissionTo($ability) ?: null;
                    stop_measure('registerPermissions-hasPermissionTo');
                    return $rez;
                }
            } catch (PermissionDoesNotExist $e) {
            }
        });

        return true;
    }

    public function forgetCachedPermissions()
    {
        $grouped = $this->permissions->groupBy('permissionable_type');
        foreach($grouped as $key => $group) {
            $cache_key = "permissions_".mb_strtolower(str_replace("\\", "_", $key));
            $this->cache->forget($cache_key);
        }
        $this->cache->forget($this->cacheKey . "_plucked");
        $this->cache->forget($this->cacheKey);
    }

    public function getPermissions(): Collection
    {

        if (!$this->permissions) {
            $this->permissions = $this->cache->remember($this->cacheKey, config('permission.cache_expiration_time'), function () {
                return app(Permission::class)->with('roles')->get();
            });
        }

        if (!$this->permissions_plucked) {
            $this->permissions_plucked = $this->cache->remember($this->cacheKey . "_plucked", config('permission.cache_expiration_time'), function () {
                return app(Permission::class)->pluck('id', 'name')->toArray();
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
        if (count($this->permissions_plucked) > 0 && array_key_exists($name, $this->permissions_plucked)) {
            $id = $this->permissions_plucked[$name];
        }
        return $id;
    }

    public function getPermissionsByNamespace($namespace){

        $namespace_cache_key = "permissions_".mb_strtolower(str_replace("\\", "_", $namespace));

        if($this->cache->has($namespace_cache_key)){
            return $this->cache->get($namespace_cache_key);
        }

        $grouped = $this->permissions->groupBy('permissionable_type');
        foreach($grouped as $key => $group){
            $cache_key = "permissions_".mb_strtolower(str_replace("\\", "_", $key));
            $this->cache->remember($cache_key, config('permission.cache_expiration_time'), function () use ($group) {
                return $group->pluck('id', 'name')->toArray();
            });
        }

        return $this->cache->get($namespace_cache_key);
    }

    public function getPermissionsByUserID($id)
    {

    }

}
