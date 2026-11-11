plugins {
    id("com.android.application")
}

android {
    namespace = "org.acme.ledger"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.acme.ledger"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
