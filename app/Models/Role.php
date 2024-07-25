<?php
namespace App\Models;

/**
 * Class Role
 *
 * @package App
 */
class Role extends BaseModel
{
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'roles';


    /**
     * @var array
     */
    protected $fillable = [
        'code',
        'name',
        'status',
        'description',
        'role_level',
        'is_active',
        'deleted',
        'updated_by',
        'created_by',
        'updated_at',
        'created_at',
    ];

}
