<?php

namespace Sonata\UserBundle\Security\RolesBuilder;

use Sonata\AdminBundle\Admin\AdminInterface;
use Sonata\AdminBundle\Admin\Pool;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Translation\TranslatorInterface;

final class GroupsAwareAdminRolesBuilder implements AdminRolesBuilderInterface
{
    /**
     * @var AuthorizationCheckerInterface
     */
    private $authorizationChecker;

    /**
     * @var Pool
     */
    private $pool;

    /**
     * @var TranslatorInterface
     */
    private $translator;

    /**
     * @var string []
     */
    private $excludeAdmins = [];

    public function __construct(
        AuthorizationCheckerInterface $authorizationChecker,
        Pool $pool,
        TranslatorInterface $translator
    ) {
        $this->authorizationChecker = $authorizationChecker;
        $this->pool = $pool;
        $this->translator = $translator;
    }

    public function getPermissionLabels(): array
    {
        $permissionLabels = [];
        foreach ($this->getRoles() as $attributes) {
            if (isset($attributes['label'])) {
                $permissionLabels[$attributes['label']] = $attributes['label'];
            }
        }

        $permissionLabelsOrder = [
            'ALL',
            'LIST',
            'VIEW',
            'CREATE',
            'EDIT',
            'DELETE',
            'EXPORT',
        ];

        usort($permissionLabels, function ($a, $b) use ($permissionLabelsOrder) {
            $aPos = array_search($a, $permissionLabelsOrder);
            $bPos = array_search($b, $permissionLabelsOrder);

            if ($aPos === false && $bPos !== false) {
                return 1;
            }

            if ($aPos !== false && $bPos === false) {
                return -1;
            }

            return $aPos - $bPos;
        });

        return $permissionLabels;
    }

    public function getExcludeAdmins(): array
    {
        return $this->excludeAdmins;
    }

    public function addExcludeAdmin(string $exclude)
    {
        $this->excludeAdmins[] = $exclude;
    }

    public function getRoles(string $domain = null): array
    {
        $roles = [];

        $adminGroups = $this->pool->getAdminGroups();
        foreach ($adminGroups as $adminGroupId => $adminGroup) {
            $adminGroupLabel = $adminGroup['label'];
            $adminGroupLabelDomain = $domain;

            foreach ($adminGroup['items'] as $item) {
                // Get admin id
                $adminId = $item['admin'];
                if (!$adminId || in_array($adminId, $this->excludeAdmins)) {
                    continue;
                }

                // Get admin
                $admin = $this->pool->getInstance($adminId);

                $admins = array_merge(
                    [$admin],
                    $admin->getChildren()
                );

                foreach ($admins as $admin) {
                    // Add roles
                    $baseRole = $admin->getSecurityHandler()->getBaseRole($admin);

                    $keys = array_keys($admin->getSecurityInformation());
                    foreach ($keys as $key) {
                        $role = sprintf($baseRole, $key);

                        $adminLabel = $admin->getLabel();
                        $adminLabelDomain = $admin->getTranslationDomain();

                        $roles[$role] = [
                            'role' => $role,
                            'label' => $key,
                            'role_translated' => $this->translateRole($role, $domain),
                            'is_granted' => $this->isMaster($admin) || $this->authorizationChecker->isGranted($role),
                            'admin_label' => sprintf(
                                '%s: %s',
                                $admin->getTranslator()->trans($adminGroupLabel, [], $adminGroupLabelDomain),
                                $admin->getTranslator()->trans($adminLabel, [], $adminLabelDomain)
                            ),
                        ];
                    }
                }
            }
        }

        return $roles;
    }

    private function isMaster(AdminInterface $admin): bool
    {
        return $admin->isGranted('MASTER') || $admin->isGranted('OPERATOR')
            || $this->authorizationChecker->isGranted($this->pool->getOption('role_super_admin'));
    }

    private function translateRole(string $role, $domain): string
    {
        if ($domain) {
            return $this->translator->trans($role, [], $domain);
        }

        return $role;
    }
}
