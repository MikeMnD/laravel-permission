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
        return $next($request);


        if (app('auth')->guest()) {
            throw UnauthorizedException::notLoggedIn();
        }

        $user_id = auth()->id();
        start_measure('PermissionRegistrar ------------------- UserPerms');
        $all_user_permissions = app(PermissionRegistrar::class)->getPermissionsByUserID($user_id);
        stop_measure('PermissionRegistrar ------------------- UserPerms');

        dd($all_user_permissions);

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
