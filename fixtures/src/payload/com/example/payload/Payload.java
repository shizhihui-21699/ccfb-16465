package com.example.payload;

public class Payload {
    private static final String C2 = "http://198.51.100.23:8080/gate.php";

    public static String collect() {
        StringBuilder sb = new StringBuilder();
        sb.append("id=");
        sb.append("abc123");
        return sb.toString();
    }

    public static void execute(String arg) throws Exception {
        String data = collect();
        System.out.println("payload ran with " + arg + " -> " + data);
    }
}
