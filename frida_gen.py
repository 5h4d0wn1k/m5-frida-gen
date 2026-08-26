"""
MO5 — Frida Script Generator
Hook generation, SSL bypass scripts, root detection bypass, class enumeration.
"""

import json
import os
import re
import sys
from typing import List, Dict, Optional, Any


class FridaScript:
    """Represents a Frida instrumentation script."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.hooks: List[Dict[str, str]] = []
        self.enumerations: List[Dict[str, str]] = []
        self.exports: List[str] = []

    def add_hook(self, class_name: str, method_name: str, implementation: str,
                 overload_types: Optional[List[str]] = None) -> None:
        hook = {
            "class": class_name,
            "method": method_name,
            "implementation": implementation,
        }
        if overload_types:
            hook["overloads"] = overload_types
        self.hooks.append(hook)

    def add_enumeration(self, target: str, pattern: str = ".*") -> None:
        self.enumerations.append({"target": target, "pattern": pattern})

    def add_export(self, function_name: str) -> None:
        self.exports.append(function_name)

    def to_frida_js(self) -> str:
        lines = []
        lines.append("// Auto-generated Frida script")
        lines.append(f"// {self.description}" if self.description else "")
        lines.append("")

        for enum_def in self.enumerations:
            target = enum_def["target"]
            pattern = enum_def["pattern"]
            lines.append(f'Java.perform(function() {{')
            lines.append(f'    var classes = Java.enumerateLoadedClasses();')
            lines.append(f'    classes.forEach(function(className) {{')
            lines.append(f'        if (className.match(/{pattern}/)) {{')
            lines.append(f'            send("[ENUM] " + className);')
            lines.append(f'        }}')
            lines.append(f'    }});')
            lines.append(f'}});')
            lines.append("")

        for hook in self.hooks:
            class_name = hook["class"]
            method = hook["method"]
            impl = hook["implementation"]
            overloads = hook.get("overloads")

            lines.append(f'Java.perform(function() {{')
            lines.append(f'    var targetClass = Java.use("{class_name}");')

            if overloads:
                for overload in overloads:
                    lines.append(f'    targetClass.{method}.overload({overload}).implementation = function() {{')
                    lines.append(f'        {impl}')
                    lines.append(f'    }};')
            else:
                lines.append(f'    targetClass.{method}.implementation = function() {{')
                lines.append(f'        {impl}')
                lines.append(f'    }};')

            lines.append(f'}});')
            lines.append("")

        for export_name in self.exports:
            lines.append(f'rpc.exports.{export_name} = function() {{')
            lines.append(f'    // TODO: implement {export_name}')
            lines.append(f'}};')

        return "\n".join(lines)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "hooks": self.hooks,
            "enumerations": self.enumerations,
            "exports": self.exports,
        }

    def save(self, output_path: str) -> bool:
        try:
            with open(output_path, "w") as f:
                f.write(self.to_frida_js())
            return True
        except IOError:
            return False

    def save_json(self, output_path: str) -> bool:
        try:
            with open(output_path, "w") as f:
                json.dump(self.to_dict(), f, indent=2)
            return True
        except IOError:
            return False


class SSLBypassGenerator:
    """Generate Frida scripts for SSL pinning bypass."""

    @staticmethod
    def bypass_okhttp3() -> str:
        return '''Java.perform(function() {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        send("[SSL] Bypassing certificate verification for: " + host);
        return untrustedChain;
    };
});'''

    @staticmethod
    def bypass_webview() -> str:
        return '''Java.perform(function() {
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
        send("[SSL] Bypassing WebView SSL error");
        handler.proceed();
    };
});'''

    @staticmethod
    def bypass_hostname_verifier() -> str:
        return '''Java.perform(function() {
    var HostnameVerifier = Java.use("javax.net.ssl.HttpsURLConnection");
    HostnameVerifier.setDefaultHostnameVerifier.implementation = function(verifier) {
        send("[SSL] Replacing hostname verifier");
        return Java.use("javax.net.ssl.HostnameVerifier").$new;
    };

    try {
        var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OkHostnameVerifier.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function() {
            send("[SSL] Bypassing OkHttp hostname verification");
            return true;
        };
    } catch(e) {}
});'''

    @staticmethod
    def bypass_trust_manager() -> str:
        return '''Java.perform(function() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustManager = Java.registerClass({
        name: "com.frida.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {
                send("[SSL] Trusting server certificate");
            },
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, TrustManagers, null);
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(km, tm, sr) {
        send("[SSL] Replacing SSLContext TrustManagers");
        this.init(km, TrustManagers, sr);
    };
});'''

    @staticmethod
    def bypass_network_security_config() -> str:
        return '''Java.perform(function() {
    var NetworkSecurityTrustManager = Java.use("android.security.net.config.NetworkSecurityTrustManager");
    NetworkSecurityTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function(chain, authType) {
        send("[SSL] Bypassing NetworkSecurityConfig trust");
    };
});'''

    @staticmethod
    def generate_all_bypasses() -> str:
        bypasses = [
            SSLBypassGenerator.bypass_okhttp3(),
            SSLBypassGenerator.bypass_webview(),
            SSLBypassGenerator.bypass_hostname_verifier(),
            SSLBypassGenerator.bypass_trust_manager(),
            SSLBypassGenerator.bypass_network_security_config(),
        ]
        header = "// Combined SSL Pinning Bypass Script\n// WARNING: For authorized testing only\n\n"
        return header + "\n\n".join(bypasses)


class RootDetectionBypassGenerator:
    """Generate Frida scripts for root detection bypass."""

    @staticmethod
    def bypass_file_checks() -> str:
        paths = [
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/su/bin/su",
        ]
        checks = "\n".join(
            f'                if (path.indexOf("{p}") !== -1) {{ return false; }}'
            for p in paths
        )
        return f'''Java.perform(function() {{
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {{
        var path = this.getAbsolutePath();
{checks}
        return this.exists();
    }};
}});'''

    @staticmethod
    def bypass_process_checks() -> str:
        return '''Java.perform(function() {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1) {
            send("[ROOT] Blocking su exec: " + cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmdArray) {
        var cmd = cmdArray.join(" ");
        if (cmd.indexOf("su") !== -1) {
            send("[ROOT] Blocking su exec: " + cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmdArray);
    };
});'''

    @staticmethod
    def bypass_package_checks() -> str:
        packages = [
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
        ]
        checks = "\n".join(
            f'                if (pkg.indexOf("{p}") !== -1) {{ return false; }}'
            for p in packages
        )
        return f'''Java.perform(function() {{
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flags) {{
{checks}
        return this.getPackageInfo(pkg, flags);
    }};
}});'''

    @staticmethod
    def bypass_binary_checks() -> str:
        return '''Java.perform(function() {
    var File = Java.use("java.io.File");
    File.canExecute.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("su") !== -1) {
            send("[ROOT] Blocking canExecute for: " + path);
            return false;
        }
        return this.canExecute();
    };

    File.canWrite.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("/system") !== -1 && path.indexOf("su") !== -1) {
            return false;
        }
        return this.canWrite();
    };
});'''

    @staticmethod
    def generate_all_bypasses() -> str:
        bypasses = [
            RootDetectionBypassGenerator.bypass_file_checks(),
            RootDetectionBypassGenerator.bypass_process_checks(),
            RootDetectionBypassGenerator.bypass_package_checks(),
            RootDetectionBypassGenerator.bypass_binary_checks(),
        ]
        header = "// Combined Root Detection Bypass Script\n// WARNING: For authorized testing only\n\n"
        return header + "\n\n".join(bypasses)


class ClassEnumerator:
    """Generate Frida scripts for class and method enumeration."""

    @staticmethod
    def enumerate_classes(pattern: str = ".*") -> str:
        return f'''Java.perform(function() {{
    Java.enumerateLoadedClasses({{
        onMatch: function(className) {{
            if (className.match(/{pattern}/)) {{
                send("[CLASS] " + className);
            }}
        }},
        onComplete: function() {{
            send("[ENUM] Class enumeration complete");
        }}
    }});
}});'''

    @staticmethod
    def enumerate_methods(class_name: str) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");
    var methods = cls.class.getDeclaredMethods();
    methods.forEach(function(method) {{
        send("[METHOD] {class_name}." + method.getName() + " " + method.toString());
    }});
}});'''

    @staticmethod
    def enumerate_fields(class_name: str) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");
    var fields = cls.class.getDeclaredFields();
    fields.forEach(function(field) {{
        send("[FIELD] {class_name}." + field.getName() + " : " + field.getType().getName());
    }});
}});'''

    @staticmethod
    def enumerate_constructors(class_name: str) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");
    var constructors = cls.class.getDeclaredConstructors();
    constructors.forEach(function(ctor) {{
        send("[CTOR] {class_name}" + ctor.toString());
    }});
}});'''

    @staticmethod
    def enumerate_interfaces(class_name: str) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");
    var interfaces = cls.class.getInterfaces();
    interfaces.forEach(function(iface) {{
        send("[IFACE] {class_name} implements " + iface.getName());
    }});
}});'''

    @staticmethod
    def full_class_dump(class_name: str) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");

    send("=== Constructors ===");
    cls.class.getDeclaredConstructors().forEach(function(c) {{
        send("  " + c.toString());
    }});

    send("=== Fields ===");
    cls.class.getDeclaredFields().forEach(function(f) {{
        send("  " + f.getType().getName() + " " + f.getName());
    }});

    send("=== Methods ===");
    cls.class.getDeclaredMethods().forEach(function(m) {{
        send("  " + m.getReturnType().getName() + " " + m.getName() + "(" + m.getParameterTypes().map(function(p) {{ return p.getName(); }}).join(", ") + ")");
    }});

    send("=== Interfaces ===");
    cls.class.getInterfaces().forEach(function(i) {{
        send("  " + i.getName());
    }});

    send("=== Superclass ===");
    send("  " + cls.class.getSuperclass().getName());
}});'''


class HookGenerator:
    """Generate custom Frida hooks from specifications."""

    @staticmethod
    def generate_constructor_hook(class_name: str) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");
    cls.$init.overloads.forEach(function(overload) {{
        overload.implementation = function() {{
            send("[CTOR] {class_name}.$init(" + Array.from(arguments).join(", ") + ")");
            return this.$init.apply(this, arguments);
        }};
    }});
}});'''

    @staticmethod
    def generate_return_value_hook(class_name: str, method_name: str) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");
    cls.{method_name}.implementation = function() {{
        var result = this.{method_name}.apply(this, arguments);
        send("[HOOK] {class_name}.{method_name}() returned: " + result);
        return result;
    }};
}});'''

    @staticmethod
    def generate_args_hook(class_name: str, method_name: str) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");
    cls.{method_name}.implementation = function() {{
        var args = Array.from(arguments);
        send("[HOOK] {class_name}.{method_name}(" + args.join(", ") + ")");
        return this.{method_name}.apply(this, arguments);
    }};
}});'''

    @staticmethod
    def generate_modifying_hook(class_name: str, method_name: str,
                                arg_index: int, new_value: Any) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");
    cls.{method_name}.overload("java.lang.String").implementation = function(arg) {{
        var original = arg;
        arg = "{new_value}";
        send("[MODIFY] {class_name}.{method_name}: " + original + " -> " + arg);
        return this.{method_name}(arg);
    }};
}});'''

    @staticmethod
    def generate_logging_hook(class_name: str, method_name: str,
                              log_file: str) -> str:
        return f'''Java.perform(function() {{
    var cls = Java.use("{class_name}");
    cls.{method_name}.implementation = function() {{
        var args = Array.from(arguments);
        var logEntry = {{
            timestamp: Date.now(),
            class: "{class_name}",
            method: "{method_name}",
            args: args
        }};
        send(JSON.stringify(logEntry));
        return this.{method_name}.apply(this, arguments);
    }};
}});'''


class ScriptBuilder:
    """Build composite Frida scripts from multiple components."""

    def __init__(self, name: str = "custom_script"):
        self.name = name
        self.components: List[str] = []

    def add_ssl_bypass(self) -> None:
        self.components.append(SSLBypassGenerator.generate_all_bypasses())

    def add_root_bypass(self) -> None:
        self.components.append(RootDetectionBypassGenerator.generate_all_bypasses())

    def add_class_enum(self, pattern: str = ".*") -> None:
        self.components.append(ClassEnumerator.enumerate_classes(pattern))

    def add_constructor_hook(self, class_name: str) -> None:
        self.components.append(HookGenerator.generate_constructor_hook(class_name))

    def add_return_hook(self, class_name: str, method: str) -> None:
        self.components.append(HookGenerator.generate_return_value_hook(class_name, method))

    def add_args_hook(self, class_name: str, method: str) -> None:
        self.components.append(HookGenerator.generate_args_hook(class_name, method))

    def add_class_dump(self, class_name: str) -> None:
        self.components.append(ClassEnumerator.full_class_dump(class_name))

    def build(self) -> str:
        header = f'// Composite Frida Script: {self.name}\n// Auto-generated by Frida Script Generator\n\n'
        return header + "\n\n".join(self.components)

    def save(self, output_path: str) -> bool:
        try:
            with open(output_path, "w") as f:
                f.write(self.build())
            return True
        except IOError:
            return False


class FridaGenerator:
    """Main Frida script generator orchestrator."""

    def __init__(self, output_dir: str = "frida_output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.scripts: List[FridaScript] = []

    def create_ssl_bypass_script(self) -> FridaScript:
        script = FridaScript("ssl_bypass", "SSL pinning bypass for Android apps")
        script.add_hook(
            "com.android.org.conscrypt.TrustManagerImpl",
            "verifyChain",
            "return untrustedChain;",
        )
        script.add_hook(
            "android.webkit.WebViewClient",
            "onReceivedSslError",
            "handler.proceed();",
        )
        self.scripts.append(script)
        return script

    def create_root_bypass_script(self) -> FridaScript:
        script = FridaScript("root_bypass", "Root detection bypass")
        script.add_hook(
            "java.io.File",
            "exists",
            "var path = this.getAbsolutePath(); if (path.indexOf('su') !== -1) { return false; } return this.exists();",
        )
        self.scripts.append(script)
        return script

    def create_class_enum_script(self, pattern: str = ".*") -> FridaScript:
        script = FridaScript("class_enum", f"Enumerate classes matching: {pattern}")
        script.add_enumeration("loaded_classes", pattern)
        self.scripts.append(script)
        return script

    def create_custom_script(self, name: str) -> FridaScript:
        script = FridaScript(name, f"Custom script: {name}")
        self.scripts.append(script)
        return script

    def build_composite(self, name: str, components: List[str]) -> str:
        builder = ScriptBuilder(name)
        for component in components:
            if component == "ssl":
                builder.add_ssl_bypass()
            elif component == "root":
                builder.add_root_bypass()
            elif component.startswith("enum:"):
                pattern = component.split(":", 1)[1]
                builder.add_class_enum(pattern)
        return builder.build()

    def save_all(self) -> List[str]:
        saved = []
        for i, script in enumerate(self.scripts):
            js_path = os.path.join(self.output_dir, f"{script.name}.js")
            json_path = os.path.join(self.output_dir, f"{script.name}.json")
            if script.save(js_path):
                saved.append(js_path)
            if script.save_json(json_path):
                saved.append(json_path)
        return saved

    def list_saved(self) -> List[str]:
        if not os.path.exists(self.output_dir):
            return []
        return [
            os.path.join(self.output_dir, f)
            for f in os.listdir(self.output_dir)
            if f.endswith((".js", ".json"))
        ]


def main():
    if len(sys.argv) < 2:
        print("Usage: frida_gen.py <command> [args]")
        print("Commands:")
        print("  ssl-bypass        - Generate SSL bypass script")
        print("  root-bypass       - Generate root detection bypass script")
        print("  class-enum <pat>  - Generate class enumeration script")
        print("  composite <name>  - Generate composite script (interactive)")
        print("  hook <class> <method> - Generate hook for specific method")
        print("  list              - List saved scripts")
        return

    cmd = sys.argv[1]
    gen = FridaGenerator()

    if cmd == "ssl-bypass":
        script = gen.create_ssl_bypass_script()
        saved = gen.save_all()
        print(f"Saved: {saved}")

    elif cmd == "root-bypass":
        script = gen.create_root_bypass_script()
        saved = gen.save_all()
        print(f"Saved: {saved}")

    elif cmd == "class-enum":
        pattern = sys.argv[2] if len(sys.argv) > 2 else ".*"
        script = gen.create_class_enum_script(pattern)
        saved = gen.save_all()
        print(f"Saved: {saved}")

    elif cmd == "composite":
        name = sys.argv[2] if len(sys.argv) > 2 else "composite"
        builder = ScriptBuilder(name)
        builder.add_ssl_bypass()
        builder.add_root_bypass()
        output = os.path.join(gen.output_dir, f"{name}.js")
        builder.save(output)
        print(f"Saved: {output}")

    elif cmd == "hook":
        if len(sys.argv) < 4:
            print("Usage: frida_gen.py hook <class_name> <method_name>")
            return
        js = HookGenerator.generate_return_value_hook(sys.argv[2], sys.argv[3])
        output = os.path.join(gen.output_dir, "hook.js")
        with open(output, "w") as f:
            f.write(js)
        print(f"Saved: {output}")

    elif cmd == "list":
        scripts = gen.list_saved()
        for s in scripts:
            print(s)

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
