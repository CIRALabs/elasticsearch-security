package ca.ciralabs;

class UserInfo {
    enum UserType {
        MASTER(7){
            @Override
            public String toString() {
                return "Master";
            }
        },
        DEVELOPER(6){
            @Override
            public String toString() {
                return "Developer";
            }
        },
        POWER_USER(5){
            @Override
            public String toString() {
                return "Power User";
            }
        },
        USER(4){
            @Override
            public String toString() {
                return "User";
            }
        },
        OLD_PASSWORD(1){
            @Override
            public String toString() {
                return "Old Password";
            }
        },
        BAD_USER(0){
            @Override
            public String toString() {
                return "Bad User";
            }
        };

        private final int userLevel;

        UserType(int userLevel) {
            this.userLevel = userLevel;
        }

        public int getUserLevel() {
            return userLevel;
        }

        public static UserType fromInteger(int userLevel) {
            if (userLevel == MASTER.getUserLevel()) {
                return MASTER;
            } else if (userLevel == DEVELOPER.getUserLevel()) {
                return DEVELOPER;
            } else if (userLevel == POWER_USER.getUserLevel()) {
                return POWER_USER;
            } else if (userLevel == USER.getUserLevel()) {
                return USER;
            } else if (userLevel == OLD_PASSWORD.getUserLevel()) {
                return OLD_PASSWORD;
            }else {
                return BAD_USER;
            }
        }
    }

    private final String username;
    private final UserType userType;
    private final boolean success;

    UserInfo() {
        username = null;
        userType = null;
        success = false;
    }

    UserInfo(String username, UserType userType, boolean success) {
        this.username = username;
        this.userType = userType;
        this.success = success;
    }

    UserType getUserType() {
        return userType;
    }

    int getUserLevel() {
        assert userType != null;
        return userType.getUserLevel();
    }

    String getUsername() {
        return username;
    }

    boolean isSuccessful() {
        return success;
    }
}
