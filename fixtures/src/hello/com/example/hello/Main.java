package com.example.hello;

public class Main {
    public static String banner() {
        return "hello from unhusk";
    }

    public static int add(int a, int b) {
        int sum = a + b;
        return sum;
    }

    public static void run() {
        String b = banner();
        int n = add(20, 22);
        if (n == 42 && b.length() > 0) {
            System.out.println(b);
        }
    }

    public static void main(String[] args) {
        run();
    }
}
