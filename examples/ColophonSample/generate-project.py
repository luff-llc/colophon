#!/usr/bin/env python3
"""Generate the dependency-free macOS/iOS template project. Run from any directory."""
from pathlib import Path
import sys
root = Path(__file__).resolve().parent
standalone = '--standalone' in sys.argv
repo = root.parents[1]
project = (repo / '.build/sample-project' if standalone else root) / 'ColophonSample.xcodeproj'
project.mkdir(parents=True, exist_ok=True)
# Stable identifiers keep regeneration reviewable.
ids = {name: f'{i:024X}' for i, name in enumerate([
    'project', 'main', 'products', 'app', 'target', 'sources', 'frameworks',
    'sourceApp', 'sourceView', 'buildApp', 'buildView', 'package', 'product', 'buildProduct',
    'projectConfigs', 'targetConfigs', 'projectDebug', 'projectRelease', 'targetDebug', 'targetRelease'], 1)}
def i(name): return ids[name]
objects = []
def obj(name, body): objects.append(f'{i(name)} = {{ {body} }};')
obj('main', f'isa = PBXGroup; children = ({i("sourceApp")}, {i("sourceView")}, {i("products")}); sourceTree = "<group>";')
obj('products', f'isa = PBXGroup; children = ({i("app")}); name = Products; sourceTree = "<group>";')
obj('app', 'isa = PBXFileReference; explicitFileType = wrapper.application; path = ColophonSample.app; sourceTree = BUILT_PRODUCTS_DIR;')
for source, name, build in [('ColophonSampleApp.swift', 'sourceApp', 'buildApp'), ('SampleView.swift', 'sourceView', 'buildView')]:
    obj(name, f'isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = {source}; sourceTree = "<group>";')
    obj(build, f'isa = PBXBuildFile; fileRef = {i(name)};')
obj('buildProduct', f'isa = PBXBuildFile; productRef = {i("product")};')
obj('sources', f'isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ({i("buildApp")}, {i("buildView")}); runOnlyForDeploymentPostprocessing = 0;')
obj('frameworks', f'isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = ({i("buildProduct")}); runOnlyForDeploymentPostprocessing = 0;')
obj('package', 'isa = XCLocalSwiftPackageReference; relativePath = ../..;')
obj('product', f'isa = XCSwiftPackageProductDependency; package = {i("package")}; productName = ColophonSession;')
obj('target', f'isa = PBXNativeTarget; buildConfigurationList = {i("targetConfigs")}; buildPhases = ({i("sources")}, {i("frameworks")}); buildRules = (); dependencies = (); name = ColophonSample; packageProductDependencies = ({i("product")}); productName = ColophonSample; productReference = {i("app")}; productType = "com.apple.product-type.application";')
for prefix in ['project', 'target']:
    obj(prefix+'Configs', f'isa = XCConfigurationList; buildConfigurations = ({i(prefix+"Debug")}, {i(prefix+"Release")}); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
    for mode in ['Debug', 'Release']:
        settings = 'SWIFT_VERSION = 6.0; SWIFT_STRICT_CONCURRENCY = complete; CLANG_ENABLE_MODULES = YES;'
        if prefix == 'target':
            settings += ' PRODUCT_BUNDLE_IDENTIFIER = org.luff.ColophonSample; PRODUCT_NAME = "$(TARGET_NAME)"; GENERATE_INFOPLIST_FILE = YES; INFOPLIST_KEY_LSApplicationCategoryType = "public.app-category.productivity"; INFOPLIST_KEY_UILaunchScreen_Generation = YES; INFOPLIST_KEY_UIApplicationSceneManifest_Generation = YES; SUPPORTED_PLATFORMS = "macosx iphoneos iphonesimulator"; SDKROOT = auto; MACOSX_DEPLOYMENT_TARGET = 14.0; IPHONEOS_DEPLOYMENT_TARGET = 17.0; TARGETED_DEVICE_FAMILY = "1,2"; CODE_SIGN_STYLE = Automatic;'
        if mode == 'Debug': settings += ' SWIFT_OPTIMIZATION_LEVEL = "-Onone"; SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;'
        obj(prefix+mode, f'isa = XCBuildConfiguration; buildSettings = {{ {settings} }}; name = {mode};')
obj('project', f'isa = PBXProject; attributes = {{ LastUpgradeCheck = 2700; }}; buildConfigurationList = {i("projectConfigs")}; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; knownRegions = (en, Base); mainGroup = {i("main")}; packageReferences = ({i("package")}); productRefGroup = {i("products")}; projectDirPath = ""; projectRoot = ""; targets = ({i("target")});')
if standalone:
    # Restricted-host mode compiles the same root-package targets without a manifest subprocess.
    objects = [entry for entry in objects if not any(entry.startswith(i(name)+' =') for name in ['package', 'product', 'buildProduct'])]
    objects = [entry.replace(f'files = ({i("buildProduct")});', 'files = ();')
               .replace(f'packageProductDependencies = ({i("product")});', 'packageProductDependencies = ();')
               .replace(f'packageReferences = ({i("package")});', 'packageReferences = ();') for entry in objects]
    for source in ['ColophonSampleApp.swift', 'SampleView.swift']:
        objects = [entry.replace(f'path = {source};', f'path = "{root / source}";') for entry in objects]
    def allocate(name):
        ids[name] = f'{len(ids)+1:024X}'
        return i(name)
    target_ids = []
    dependency_ids = []
    library_names = ['ColophonKit', 'ColophonKitStorage', 'ColophonSession']
    for module in library_names:
        for suffix in ['Target', 'Product', 'Sources', 'Configs', 'Debug', 'Release', 'Dependency']:
            allocate(module+suffix)
        target_ids.append(i(module+'Target'))
        dependency_ids.append(i(module+'Dependency'))
        obj(module+'Dependency', f'isa = PBXTargetDependency; target = {i(module+"Target")};')
        obj(module+'Product', f'isa = PBXFileReference; explicitFileType = archive.ar; path = lib{module}.a; sourceTree = BUILT_PRODUCTS_DIR;')
        builds = []
        for index, source in enumerate(sorted((repo / 'swift/Sources' / module).rglob('*.swift'))):
            ref, build = module+f'File{index}', module+f'Build{index}'
            allocate(ref); allocate(build)
            obj(ref, f'isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = "{source}"; sourceTree = "<absolute>";')
            obj(build, f'isa = PBXBuildFile; fileRef = {i(ref)};')
            builds.append(i(build))
        obj(module+'Sources', f'isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ({", ".join(builds)}); runOnlyForDeploymentPostprocessing = 0;')
        deps = ', '.join(dependency_ids[:-1]) if module == 'ColophonSession' else ''
        obj(module+'Target', f'isa = PBXNativeTarget; buildConfigurationList = {i(module+"Configs")}; buildPhases = ({i(module+"Sources")}); buildRules = (); dependencies = ({deps}); name = {module}; productName = {module}; productReference = {i(module+"Product")}; productType = "com.apple.product-type.library.static";')
        obj(module+'Configs', f'isa = XCConfigurationList; buildConfigurations = ({i(module+"Debug")}, {i(module+"Release")}); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
        includes = f'SWIFT_INCLUDE_PATHS = "{repo}/sdk/apple/ColophonFFI.xcframework/$(COLOPHON_FFI_SLICE)/Headers";'
        common = f'SWIFT_VERSION = 6.0; SWIFT_STRICT_CONCURRENCY = complete; PRODUCT_NAME = {module}; PRODUCT_MODULE_NAME = {module}; DEFINES_MODULE = YES; SKIP_INSTALL = YES; SUPPORTED_PLATFORMS = "macosx iphoneos iphonesimulator"; MACOSX_DEPLOYMENT_TARGET = 14.0; IPHONEOS_DEPLOYMENT_TARGET = 17.0; {includes}'
        common += ' "COLOPHON_FFI_SLICE[sdk=macosx*]" = "macos-arm64"; "COLOPHON_FFI_SLICE[sdk=iphoneos*]" = "ios-arm64"; "COLOPHON_FFI_SLICE[sdk=iphonesimulator*]" = "ios-arm64-simulator";'
        for mode in ['Debug', 'Release']:
            obj(module+mode, f'isa = XCBuildConfiguration; buildSettings = {{ {common} }}; name = {mode};')
    libraries = ' '.join(f'"$(BUILT_PRODUCTS_DIR)/lib{module}.a",' for module in library_names)
    settings = f'OTHER_LDFLAGS = ({libraries} "{repo}/sdk/apple/ColophonFFI.xcframework/$(COLOPHON_FFI_SLICE)/libcolophon_ffi.a", "-lresolv"); {includes}'
    settings += ' "COLOPHON_FFI_SLICE[sdk=macosx*]" = "macos-arm64"; "COLOPHON_FFI_SLICE[sdk=iphoneos*]" = "ios-arm64"; "COLOPHON_FFI_SLICE[sdk=iphonesimulator*]" = "ios-arm64-simulator";'
    objects = [entry.replace('dependencies = ();', f'dependencies = ({", ".join(dependency_ids)});') if entry.startswith(i('target')+' =') else entry for entry in objects]
    objects = [entry.replace(f'targets = ({i("target")});', f'targets = ({i("target")}, {", ".join(target_ids)});') for entry in objects]
    objects = [entry.replace('buildSettings = {', 'buildSettings = { '+settings) if any(entry.startswith(i('target'+mode)+' =') for mode in ['Debug', 'Release']) else entry for entry in objects]
(project / 'project.pbxproj').write_text('// !$*UTF8*$!\n{ archiveVersion = 1; classes = {}; objectVersion = 56; objects = {\n'+'\n'.join(objects)+f'\n}}; rootObject = {i("project")}; }}\n')
schemes = project / 'xcshareddata/xcschemes'
schemes.mkdir(parents=True, exist_ok=True)
(schemes / 'ColophonSample.xcscheme').write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2700" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{i('target')}" BuildableName="ColophonSample.app" BlueprintName="ColophonSample" ReferencedContainer="container:ColophonSample.xcodeproj"/></BuildActionEntry></BuildActionEntries></BuildAction>
<LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{i('target')}" BuildableName="ColophonSample.app" BlueprintName="ColophonSample" ReferencedContainer="container:ColophonSample.xcodeproj"/></BuildableProductRunnable></LaunchAction>
<ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>''')
print(project)
