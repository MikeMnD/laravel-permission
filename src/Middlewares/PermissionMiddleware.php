<?php

namespace Spatie\Permission\Middlewares;

use App\Models\Permission;
use Closure;
use Illuminate\Support\Facades\Auth;
use Spatie\Permission\Exceptions\UnauthorizedException;
use Spatie\Permission\PermissionRegistrar;

class PermissionMiddleware
{



    public function handle($request, Closure $next, $permission)
    {
        if (app('auth')->guest()) {
            throw UnauthorizedException::notLoggedIn();
        }

        $user_id = auth()->id();


        start_measure('PermissionRegistrar ------------------- UserPerms');
        $PR = app(PermissionRegistrar::class);
        if(array_key_exists($user_id, $PR->users_permissions)){
            $all_user_permissions = $PR->users_permissions[$user_id];
        } else {
            $all_user_permissions = app('auth')->user()->getAllPermissionsIDs();
            $PR->users_permissions[$user_id] = $all_user_permissions;
        }
         stop_measure('PermissionRegistrar ------------------- UserPerms');

        $permissions = is_array($permission)
            ? $permission
            : explode('|', $permission);

        foreach ($permissions as $permission) {

            if ( starts_with($permission, 'model#')) {

                $model = str_after($permission, "model#");
                $namespace = "App\\Models\\" . $model;
                $model_all_permissions_ids = $PR->getPermissionsByNamespace("App\Models\DocumentCategory");
                start_measure('array_intersect');
                $intersected_permissions = array_intersect($model_all_permissions_ids, $all_user_permissions);
                stop_measure('array_intersect');
                if (count($intersected_permissions) > 1) {
                    return $next($request);
                }
            }

            if (app('auth')->user()->can($permission)) {
                return $next($request);
            }



        }

        throw UnauthorizedException::forPermissions($permissions);
    }
}
