//! A "wiggle" test: run a sample through a broad slice of the framework model
//! and assert that nothing panics and that the common paths are actually
//! modelled (not just answered with a default).

mod support;

use std::sync::Arc;

use support::packed::compile_sources_to_dex;
use unshroud::dex::DexFile;
use unshroud::vm::android::AndroidHost;
use unshroud::vm::env::{Environment, Persona};
use unshroud::vm::interp::Vm;
use unshroud::vm::registry::Registry;

const SOURCE: &str = r#"
package com.example.api;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.Base64;
import java.util.*;
import org.json.JSONObject;

public class Api {
    public static String exercise(Context ctx) throws Exception {
        StringBuilder out = new StringBuilder();

        // 1. Device identity
        out.append(Build.MODEL).append('|');
        out.append(Build.MANUFACTURER).append('|');
        out.append(Build.VERSION.SDK_INT).append('|');
        String androidId = Settings.Secure.getString(ctx.getContentResolver(), "android_id");
        out.append(androidId).append('|');

        // 2. Telephony
        TelephonyManager tm = (TelephonyManager) ctx.getSystemService("phone");
        out.append(tm.getDeviceId()).append('|');
        out.append(tm.getSimOperator()).append('|');

        // 3. Collections and sorting
        List<String> list = new ArrayList<String>();
        list.add("b"); list.add("a"); list.add("c");
        Collections.sort(list);
        for (String s : list) out.append(s);
        Map<String, String> map = new HashMap<String, String>();
        map.put("k1", "v1"); map.put("k2", "v2");
        out.append(map.get("k1")).append('|');

        // 4. Base64 and JSON round trip
        byte[] raw = "payload".getBytes();
        String b64 = Base64.encodeToString(raw, Base64.NO_WRAP);
        out.append(b64).append('|');
        JSONObject json = new JSONObject();
        json.put("imei", tm.getDeviceId());
        json.put("model", Build.MODEL);
        out.append(json.toString()).append('|');

        // 5. SharedPreferences persistence across calls
        SharedPreferences sp = ctx.getSharedPreferences("cfg", 0);
        sp.edit().putString("token", "abc123").commit();
        out.append(sp.getString("token", "")).append('|');

        // 6. Regex and string ops
        String csv = "1,2,3";
        String[] parts = csv.split(",");
        out.append(parts.length).append('|');
        out.append("Hello".toLowerCase()).append('|');
        out.append(String.format("%05d", 42));

        return out.toString();
    }
}
"#;

#[test]
fn broad_api_surface_is_modelled() {
    let Some(dex) = compile_sources_to_dex(&[("Api", SOURCE)]) else { return };
    let mut reg = Registry::new();
    reg.add_image(Arc::new(DexFile::parse("classes.dex", dex).unwrap()), false);
    let mut vm = Vm::new(reg, Environment::new(Persona::retail_default()), 5_000_000, 10_000);
    let mut host = AndroidHost::new();
    let ctx = vm.new_instance_of("Landroid/content/Context;").unwrap();
    let e = vm.find_method("Lcom/example/api/Api;", "exercise", "(Landroid/content/Context;)Ljava/lang/String;").unwrap();
    let r = vm.execute(&mut host, e, vec![unshroud::vm::value::Slot::reference(ctx)]);
    let out = r.map(|s| vm.str_of_slot(s)).unwrap_or(None).unwrap_or_default();
    eprintln!("result: {out}");
    eprintln!("gaps: {:#?}", vm.env.coverage_gaps);

    // The value must actually contain the device facts, not defaults.
    assert!(out.contains("SM-G991B"), "Build.MODEL missing: {out}");
    assert!(out.contains("samsung"), "manufacturer missing");
    assert!(out.contains("31"), "SDK_INT missing");
    assert!(out.contains("3f7c1a90b2d4e8f1"), "android_id missing");
    assert!(out.contains("354918476201935"), "imei missing");
    assert!(out.contains("abc"), "sorted list wrong: {out}");
    assert!(out.contains("v1"), "map lookup missing");
    assert!(out.contains("cGF5bG9hZA=="), "base64 missing (payload): {out}");
    assert!(out.contains("\"imei\":\"354918476201935\""), "json missing: {out}");
    assert!(out.contains("abc123"), "prefs missing");
    // `append(char)` appends the character itself, not its int value.
    assert!(out.contains("3|hello|00042"), "string ops missing: {out}");

    // For the paths above, nothing should have fallen through to a default.
    let critical_gaps = ["getDeviceId", "Build", "JSONObject", "split", "format",
                          "getSharedPreferences", "Base64", "getString", "getModel"];
    for g in critical_gaps {
        let hit = vm.env.coverage_gaps.keys().any(|k| k.contains(g));
        assert!(!hit, "unexpected gap for {g}: {:?}", vm.env.coverage_gaps);
    }
}
