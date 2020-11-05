package com.itheima.service;

import com.itheima.health.pojo.Permission;
import com.itheima.health.pojo.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * <p>
 *
 * </p>
 *
 * @author: Eric
 * @since: 2020/10/31
 */
public class UserService implements UserDetailsService {
    /**
     * 获取登陆用户信息
     *
     * @param username 从前端传过来的用户名
     * @return 用户名，密码，权限集合
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 假设从数据库查询, 从数据库查询到的用户信息（用户名，密码，角色，权限）
        com.itheima.health.pojo.User userInDb = findByUsername(username);
        if(null != userInDb){
            // 授权, userDetail是security需要的
            //String username, 用户名
            //String password, 密码，必须是从数据库查询到的密码
            //Collection<? extends GrantedAuthority> authorities 用户的权限集合
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            // 遍历用户的角色与权限
            // 用户拥有的角色
            Set<Role> roles = userInDb.getRoles();
            if(null != roles){
                GrantedAuthority sga = null;
                for (Role role : roles) {
                    // 角色名, 授予角色
                    sga = new SimpleGrantedAuthority(role.getKeyword());
                    authorities.add(sga);
                    // 授予权限, 这个角色下所拥有的权限
                    Set<Permission> permissions = role.getPermissions();
                    if(null != permissions){
                        for (Permission permission : permissions) {
                            // 授予权限
                            sga = new SimpleGrantedAuthority(permission.getKeyword());
                            authorities.add(sga);
                        }
                    }
                }
            }

            User securityUser = new User(username, userInDb.getPassword(),authorities);
            return securityUser;

        }
        return null;
    }

    /**
     * 这个用户admin/admin, 有ROLE_ADMIN角色，角色下有ADD_CHECKITEM权限
     * 假设从数据库查询
     * @param username
     * @return
     */
    private com.itheima.health.pojo.User findByUsername (String username){
        if("admin".equals(username)) {
            com.itheima.health.pojo.User user = new com.itheima.health.pojo.User();
            user.setUsername("admin");
            // 使用密文，删除{noop}
            user.setPassword("$2a$10$IfPkaV5WRkaaoDODWPLU9uxQgt3qzfVUj1PxnzNPyiY.C7ycQRvAm");

            // 角色
            Role role = new Role();
            role.setKeyword("ROLE_ADMIN");

            // 权限
            Permission permission = new Permission();
            permission.setKeyword("ADD_CHECKITEM");

            // 给角色添加权限
            role.getPermissions().add(permission);

            // 把角色放进集合
            Set<Role> roleList = new HashSet<Role>();
            roleList.add(role);

            role = new Role();
            role.setKeyword("ABC");
            roleList.add(role);

            // 设置用户的角色
            user.setRoles(roleList);
            return user;
        }
        return null;
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        // 加密密码
        //System.out.println(encoder.encode("1234"));
        // 校验密码, 第1个参数为明文，第2个为密文
        System.out.println(encoder.matches("1234", "$2a$10$C2I8PHWnBtqMJlvKD7DsCuP9Kl4uQT4TIqBTgda1y/Pekp6Tb/4GO"));
        System.out.println(encoder.matches("1234", "$2a$10$IfPkaV5WRkaaoDODWPLU9uxQgt3qzfVUj1PxnzNPyiY.C7ycQRvAm"));
        System.out.println(encoder.matches("1234", "$2a$10$u/BcsUUqZNWUxdmDhbnoeeobJy6IBsL1Gn/S0dMxI2RbSgnMKJ.4a"));

    }
}
