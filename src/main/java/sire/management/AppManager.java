/*
 * Copyright 2023 Tiago Carvalho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sire.management;

import java.util.*;

public class AppManager {
    private final Map<AppAdmin, List<String>> appAdmins;
    private static AppManager instance = null;

    public static AppManager getInstance() {
        if(instance == null)
            instance = new AppManager();
        return instance;
    }

    private AppManager() {
        appAdmins = new HashMap<>();
        appAdmins.put(new AppAdmin("admin", "appadmin"), new ArrayList<>(Arrays.asList("app1", "app2","app3")));
    }

    public void createAdmin(String admin, String password) {
        appAdmins.put(new AppAdmin(admin, password), new ArrayList<>());
    }
    public void removeAdmin(String admin) {
        for(AppAdmin a : appAdmins.keySet())
            if(a.getUsername().equals(admin))
                appAdmins.remove(a);
    }
    public List<String> getAllAdmins() {
        List<String> res = new ArrayList<>();
        for(AppAdmin a : appAdmins.keySet())
            res.add(a.getUsername());
        return res;
    }

    public void addApp(String admin, String app) {
        for(AppAdmin a : appAdmins.keySet())
            if(a.getUsername().equals(admin))
                appAdmins.get(a).add(app);
    }

    public void removeApp(String admin, String app) {
        for(AppAdmin a : appAdmins.keySet())
            if(a.getUsername().equals(admin))
                appAdmins.get(a).remove(app);
    }

    public List<String> getAppsFromAdmin(String admin) {
        for(AppAdmin a : appAdmins.keySet()) {
            if (a.getUsername().equals(admin))
                return appAdmins.get(a);
        }
        return null;
    }

    private static class AppAdmin {
        private final String username;
        private final String password;

        public AppAdmin(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }

}
