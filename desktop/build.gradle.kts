import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    kotlin("jvm")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.compose")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core"))
    implementation(compose.desktop.currentOs)
    // compose.desktop.currentOs bundles Material 2; we use Material 3.
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.8.1")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

tasks.test {
    useJUnitPlatform()
}

// java.smartcardio lives outside the java.se aggregate. The smartcard driver
// is written in Java specifically because javac handles --add-modules cleanly
// (Kotlin compile fights with non-default JDK modules). jpackage also needs
// the module declared so the bundled JRE in the .deb includes it.
tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(listOf("--add-modules", "java.smartcardio"))
}
compose.desktop.application.nativeDistributions.modules("java.smartcardio")

// Compose Desktop's `packageName` is reused as both (a) the Debian package
// identifier — which must be lowercase + dashes — and (b) the .desktop Name
// field shown in the app drawer. Since we can't have it both ways, we run a
// finalizing step after packageDeb that rewrites the Name= line inside the
// .deb's bundled .desktop file. dpkg-deb -R/-b round-trips the archive.
val desktopNiceName = "Anon PGP"

tasks.register("polishDeb") {
    description = "Rewrites Name= in the bundled .desktop file post-jpackage."
    val debDirProvider = layout.buildDirectory.dir("compose/binaries/main/deb")
    doLast {
        val debDir = debDirProvider.get().asFile
        val debs = debDir.listFiles { f -> f.name.endsWith(".deb") } ?: emptyArray()
        if (debs.isEmpty()) {
            logger.warn("polishDeb: no .deb files found under $debDir")
            return@doLast
        }
        for (deb in debs) {
            val work = File(deb.parentFile, deb.nameWithoutExtension + "-work")
            work.deleteRecursively()
            exec { commandLine("dpkg-deb", "-R", deb.absolutePath, work.absolutePath) }
            var patched = 0
            work.walkTopDown().filter { it.isFile && it.name.endsWith(".desktop") }.forEach { f ->
                val before = f.readText()
                var after = before.replace(
                    Regex("^Name=.*$", RegexOption.MULTILINE),
                    "Name=$desktopNiceName"
                )
                // Required for GNOME (and most shells) to map the running
                // window's WM_CLASS to this .desktop entry — so the dock
                // shows our custom icon instead of a generic fallback.
                // Main.kt sets awtAppClassName to "anon-pgp" via reflection.
                if (!after.contains("StartupWMClass=")) {
                    after = after.trimEnd() + "\nStartupWMClass=anon-pgp\n"
                }
                if (before != after) { f.writeText(after); patched++ }
            }
            // Patch the Debian control file: add a Recommends line for the
            // PCSC userspace + daemon. These are only needed when the user
            // plugs in a smartcard, so Recommends (not Depends) is the
            // honest scope — `apt install` pulls them by default but won't
            // refuse installation on systems without smartcards.
            val control = File(work, "DEBIAN/control")
            if (control.exists()) {
                val text = control.readText()
                if (!text.contains(Regex("^Recommends:", RegexOption.MULTILINE))) {
                    // Insert after Depends: so the field ordering matches dpkg conventions.
                    val patched2 = text.replace(
                        Regex("^Depends:.*$", RegexOption.MULTILINE),
                        { m -> m.value + "\nRecommends: pcscd, libpcsclite1" }
                    )
                    control.writeText(patched2)
                }
            }
            exec { commandLine("dpkg-deb", "-b", work.absolutePath, deb.absolutePath) }
            work.deleteRecursively()
            logger.lifecycle("polishDeb: patched $patched .desktop file(s) in ${deb.name}")
        }
    }
}

// Compose Desktop registers packageDeb lazily, so the lookup has to happen
// after this script's plugins block has finished evaluating.
afterEvaluate {
    tasks.named("packageDeb") { finalizedBy("polishDeb") }
}

compose.desktop {
    application {
        mainClass = "gratis.anon.pgp.desktop.MainKt"

        nativeDistributions {
            // Linux-first: deb for Debian/Ubuntu installers, AppImage for the
            // distro-agnostic single-file path. Both produced by jpackage and
            // bundle a stripped JRE so end users don't need Java installed.
            targetFormats(TargetFormat.Deb, TargetFormat.AppImage)
            packageName = "anon-pgp"
            packageVersion = "0.3.6"
            description = "Anon PGP — local-only OpenPGP suite with post-quantum keys"
            vendor = "anonymous.gratis"
            licenseFile.set(rootProject.file("LICENSE"))

            linux {
                packageName = "anon-pgp"
                debMaintainer = "admin@anon.gratis"
                menuGroup = "Utility;Security"
                appCategory = "Utility"
                shortcut = true
                // Custom launcher icon — Anonymous mask + PGP key art, with
                // the cyan border stripped to match anon-browser's style.
                iconFile.set(project.file("icons/anon-pgp.png"))
            }
        }
    }
}
