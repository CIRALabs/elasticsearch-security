package ca.ciralabs;

class UserInfo {
    enum UserType {
        MASTER(7),
        DEVELOPER(6),
        POWER_USER(5),
        USER(4),
        BADUSER(0);

        private final int userLevel;

        UserType(int userLevel) {
            this.userLevel = userLevel;
        }

        public int getUserLevel() {
            return userLevel;
        }

        public static UserType fromInteger(int userLevel) {
            if (userLevel == MASTER.getUserLevel()){
                return MASTER;
            }else if (userLevel == DEVELOPER.getUserLevel()){
                return DEVELOPER;
            }else if (userLevel == POWER_USER.getUserLevel()){
                return POWER_USER;
            }else if (userLevel == USER.getUserLevel()){
                return USER;
            }else {
                return BADUSER;
            }
        }
    }

    private final String username;
    private final UserType userType;
    private final boolean success;

    UserInfo(String username, UserType userType, boolean success) {
        this.username = username;
        this.userType = userType;
        this.success = success;
    }

    UserType getUserType() {
        return userType;
    }

    int getUserLevel() {
        return userType.getUserLevel();
    }

    String getUsername() {
        return username;
    }

    boolean isSuccessful() {
        return success;
    }
}
