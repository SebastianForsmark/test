class Logger {
    private static final boolean ENABLE_LOGGING = true;

    static void log(String message) {
        if (ENABLE_LOGGING) {
            System.out.println(message);
        }
    }
}
