package com.example.lam;

import java.util.ArrayList;
import java.util.List;

/**
 * Exercises `invoke-custom`: every lambda in the source becomes a call-site
 * whose bootstrap is LambdaMetafactory, with a method handle to the real body.
 * A VM that cannot follow call sites sees an empty program here.
 */
public class Main {
    interface Op {
        int apply(int x);
    }

    static int increment(int x) {
        return x + 1;
    }

    static int doubler(int x) {
        return x * 2;
    }

    public static int run() {
        Op a = Main::increment;      // static method reference
        Op b = Main::doubler;
        int total = 0;
        for (int i = 0; i < 5; i++) {
            total = b.apply(a.apply(total));
        }
        List<Integer> xs = new ArrayList<>();
        xs.add(total);
        int sum = 0;
        for (Integer v : xs) {
            sum += v;
        }
        return sum;
    }

    public static void main(String[] args) {
        System.out.println(run());
    }
}
