#include "Include.h"
#include "yara.h" 
#include <filesystem>
#include <sstream> 

namespace fs = std::filesystem;

std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule) {
    genericRules.push_back({ name, rule });
}

void compiler_error_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data) {

    fprintf(stderr, "YARA Compiler ");
    switch (error_level) {
    case YARA_ERROR_LEVEL_ERROR:
        fprintf(stderr, "Error");
        break;
    case YARA_ERROR_LEVEL_WARNING:
        fprintf(stderr, "Warning");
        break;
    default:
        fprintf(stderr, "Message");
        break;
    }
    if (file_name) {
        fprintf(stderr, " in %s", file_name);
    }
    if (line_number > 0) {
        fprintf(stderr, "(%d)", line_number);
    }
    fprintf(stderr, ": %s\n", message);
}

int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        std::vector<std::string>* matched_rules_ptr = static_cast<std::vector<std::string>*>(user_data);
        if (matched_rules_ptr) {
            matched_rules_ptr->push_back(rule->identifier);
        }
    }
    return CALLBACK_CONTINUE;
}

void initializeGenericRules() {

    addGenericRule("Specifics B", R"(
import "pe" 

rule cheat
{
  meta:
    description = "hellomoto"

  strings:
    $a1 = "Valorant-ColorBot.pdb" nocase
    $a2 = "XRC Products" nocase
    $a3 = "Enable Chams" nocase
    $a4 = "Load Esp" nocase
    $a5 = "Fuck Log" nocase
    $a6 = "3.142.247.110" nocase
    $a7 = "Clean Traces" nocase
    $a8 = "libil2cpp.so" nocase
    $a9 = "poco-poco" nocase
    $a10 = "Iniciando Bypass" nocase
    $a11 = "user-agent: xrc" nocase
    $a12 = "Precision Priv" nocase
    $a13 = "falconmemx64" nocase
    $a14 = "costura.memory.dll.compressed" nocase
    $a15 = "glDrawElementsInstacedBaseVertex" nocase
    $a16 = "XRCService" nocase
    $a17 = "Load Chams" nocase
    $a18 = "antena" nocase
    $a19 = "chams" nocase
    $a20 = "aimbot" nocase
    $a21 = "unpained-nonjudicative-yuette.ngrok-free.dev" nocase
    $a22 = "hitlojas.squareweb.app" nocase
    $a23 = "lidiamartinipsicologia.com" nocase
    $a24 = "bscamisas.online" nocase
    $a25 = "177.135.117.23" nocase
    $a26 = "fluxauth.com" nocase
    $a27 = "isDriverMapped" nocase
    $a28 = "MapDriverSilent" nocase
    $a29 = "vsbypass" nocase


  condition:
    any of ($a*)
}
    
)");

    addGenericRule("entropy", R"(
import "math"

rule entropy
{
  meta:
    Author = "DosX"

  condition:
    uint32(uint32(0x3C)) == 0x00004550 and
    math.entropy(0, filesize) >= 7.0
}
)");

    addGenericRule("murielson", R"(

rule empacotamentoruim
{
    strings:
        $section1 = "UPX0"
        $section2 = "UPX1"
        $section3 = "UPX2"
        $versionId = "UPX!"
    condition:
            any of them
}


)");

    addGenericRule("Obfuscated__FakeSignatures", R"(
rule Obfuscated__FakeSignatures
{
    meta:
        Author = "DosX"
    strings:
        $_1 = "Xenocode.Client.Attributes.AssemblyAttributes.ProcessedByXenocode"
        $_2 = "CryptoObfuscator.ProtectedWithCryptoObfuscatorAttribute"
        $_3 = "SecureTeam.Attributes.ObfuscatedByAgileDotNetAttribute"
        $_4 = "Xenocode.Client.Attributes.AssemblyAttributes"
        $_5 = "SmartAssembly.Attributes.PoweredByAttribute"
        $_6 = "ObfuscatedByAgileDotNetAttribute"
        $_7 = "NineRays.Obfuscator.Evaluation"
        $_8 = "ObfuscatedByCliSecureAttribute"
        $_9 = "BabelObfuscatorAttribute"
        $_10 = "AsStrongAsFuckAttribute"
        $_11 = "Macrobject.Obfuscator"
        $_12 = "DotfuscatorAttribute"
        $_13 = "CodeWallTrialVersion"
        $_14 = "ConfusedByAttribute"
        $_15 = "ObfuscatedByGoliath"
        $_16 = "NETSpider.Attribute"
        $_17 = "NineRays.Obfuscator"
        $_18 = "PoweredByAttribute"
        $_19 = "RustemSoft.Skater"
        $_20 = "BabelAttribute"
        $_21 = "YanoAttribute"
        $_22 = "EMyPID_8234_"
        $_23 = "ZYXDNGuarder"
        $_24 = "Sixxpack"
        $_25 = "____KILL"
        $_26 = "Reactor"
    condition:
        2 of them
}
)");


    addGenericRule("fake_anydesk_dotnet", R"(
import "pe"
rule fake_anydesk_dotnet {
    strings:
        $anydesk = "AnyDesk" nocase
        $mscoree = "mscoree.dll" nocase
        $runtime = "Runtime" nocase
    condition:
        pe.is_pe and $anydesk and ($mscoree or $runtime) and 
        (pe.imports("mscoree.dll", "_CorExeMain") or pe.imports("mscoree.dll", "_CorDllMain"))
})");

    addGenericRule("anydesk_cheat_bruxomem", R"(
rule anydesk_cheat_bruxomem {
    strings:
        $anydesk = "AnyDesk" nocase
        $fody = "ProcessedByFody" nocase
        $bruxo = "BruxoMem" nocase
        $aimbot = "Aimboton" nocase
        $aobscan = "AoBScan" nocase
        $camhack = "Camera Hack" nocase
        $galib = "Red.GALIB" nocase
        $antivm1 = "VBoxMouse.sys" nocase
        $antivm2 = "VMware Tools" nocase
        $antivm3 = "virtual machine" nocase
        $harmony = "0Harmony.dll" nocase
        $obfuscator = "Inx .NET Obfuscator" nocase
        $hdplayer = "HD-Player.exe" nocase
    condition:
        $anydesk and 2 of ($fody, $bruxo, $aimbot, $aobscan, $camhack, $galib, $antivm*, $harmony, $obfuscator, $hdplayer)
})");

    addGenericRule("HIGH_ENTROPY", R"(
import "math"
rule HIGH_ENTROPY {
    condition:
        math.entropy(0, filesize) > 7.0
})");

    addGenericRule("HIGH_ENTROPY_SECTION", R"(
import "pe"
import "math"
rule HIGH_ENTROPY_SECTION {
    condition:
        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0
        )
})");

    addGenericRule("cheat_frameworks", R"(
rule cheat_frameworks
{
  meta:
    description = "Frameworks universais de cheats, hooks e mappers"
  strings:
    $imgui1 = "Dear ImGui" nocase
    $imgui2 = "ImGui::CreateContext" nocase
    $imgui3 = "ProggyClean.ttf" nocase
    $imgui4 = "imgui_impl_win32" nocase
    $imgui5 = "imgui_impl_dx11" nocase
    $imgui6 = "imgui_impl_opengl" nocase

    $hook1 = "MH_Initialize" nocase
    $hook2 = "MH_CreateHook" nocase
    $hook3 = "kiero::init" nocase
    $hook4 = "kiero::bind" nocase
    $hook5 = "DetourTransactionBegin" nocase
    $hook6 = "DetourAttach" nocase

    $map1 = "kdmapper" nocase
    $map2 = "drvmap" nocase
    $map3 = "iqvw64e.sys" nocase
    $map4 = "gdrv.sys" nocase
    $map5 = "mhyprot2.sys" nocase
    $map6 = "RTCore64.sys" nocase

  condition:
    2 of ($imgui*) or any of ($hook*) or any of ($map*)
}
)");

    addGenericRule("freefire_cheat_bypass", R"(
rule freefire_cheat_bypass
{
  meta:
    description = "Deteccao de cheats, AOB scanners e bypasses para Free Fire em emuladores"
  strings:
    $emu1 = "HD-Player.exe" nocase
    $emu2 = "dnplayer.exe" nocase
    $emu3 = "LdVBoxHeadless.exe" nocase
    $emu4 = "TitanEngine.exe" nocase
    $emu5 = "AndroidProcess.exe" nocase
    $emu6 = "MEmuConsole.exe" nocase
    $emu7 = "SmartGaGa" nocase

    $pkg1 = "com.dts.freefireth" nocase
    $pkg2 = "com.dts.freefiremax" nocase
    $pkg3 = "libil2cpp.so" nocase
    $pkg4 = "libunity.so" nocase

    $feat1 = "BruxoMem" nocase
    $feat2 = "Aimboton" nocase
    $feat3 = "AoBScan" nocase
    $feat4 = "Camera Hack" nocase
    $feat5 = "antena" nocase
    $feat6 = "holograma" nocase
    $feat7 = "bala magica" nocase
    $feat8 = "magic bullet" nocase
    $feat9 = "headshot 100%" nocase
    $feat10 = "bypass emulador" nocase
    $feat11 = "bypass mobile" nocase
    $feat12 = "bypass ff" nocase
    $feat13 = "fake device" nocase
    $feat14 = "vboxmouse.sys" nocase
    $feat15 = "vboxguest.sys" nocase
    $feat16 = "mod menu ff" nocase
    $feat17 = "regedit ff" nocase
    $feat18 = "sensi ff" nocase
    $feat19 = "auxilio de mira" nocase
    $feat20 = "falconmem" nocase
    $feat21 = "Memory.dll" nocase

  condition:
    (any of ($emu*) and any of ($feat*)) or
    (any of ($pkg*) and any of ($feat*)) or
    2 of ($feat*)
}
)");

}

static std::wstring utf8_to_wstring(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &ws[0], len);
    return ws;
}

bool scan_with_yara(const std::string& path,
    std::vector<std::string>& matched_rules,
    YR_RULES* rules)
{
    if (!rules)
        return false;

    matched_rules.clear();
    std::wstring wpath = utf8_to_wstring(path);

    HANDLE hFile = CreateFileW(
        wpath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER filesize;
    if (!GetFileSizeEx(hFile, &filesize) || filesize.QuadPart > SIZE_MAX) {
        CloseHandle(hFile);
        return false;
    }

    size_t size = static_cast<size_t>(filesize.QuadPart);
    auto buffer = std::make_unique<BYTE[]>(size);

    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, buffer.get(), (DWORD)size, &bytesRead, nullptr);
    CloseHandle(hFile);

    if (!ok || bytesRead != size)
        return false;

    int result = yr_rules_scan_mem(
        rules,
        buffer.get(),
        size,
        SCAN_FLAGS_FAST_MODE,
        yara_callback,
        &matched_rules,
        0
    );


    return !matched_rules.empty();
}

void initializateCustomRules() {
    std::string ownDirectory = getOwnDirectory();

    for (const auto& entry : fs::directory_iterator(ownDirectory)) {
        if (entry.is_regular_file() && entry.path().extension() == ".yar") {
            std::string filePath = entry.path().string();

            printf("Found and processing custom rule file: %s\n", filePath.c_str());

            std::ifstream file(entry.path());
            if (!file.is_open()) {
                fprintf(stderr, "Failed to open custom rule file: %s\n", filePath.c_str());
                continue;
            }

            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string ruleContent = buffer.str();

            if (ruleContent.empty()) {
                fprintf(stderr, "Custom rule file is empty: %s\n", filePath.c_str());
                continue;
            }

            YR_COMPILER* validation_compiler = nullptr;
            if (yr_compiler_create(&validation_compiler) != ERROR_SUCCESS) {
                fprintf(stderr, "Failed to create YARA compiler for validating rule file: %s\n", filePath.c_str());
                continue;
            }

            yr_compiler_set_callback(validation_compiler, compiler_error_callback, nullptr);

            int compile_errors = yr_compiler_add_string(validation_compiler, ruleContent.c_str(), entry.path().filename().string().c_str());

            yr_compiler_destroy(validation_compiler);

            if (compile_errors == 0) {

                std::string ruleName = entry.path().stem().string();
                addGenericRule(ruleName, ruleContent);
                printf("Successfully validated and queued custom rule: %s\n", ruleName.c_str());
            }
            else {
                fprintf(stderr, "Failed to compile/validate YARA rule from file: %s. Errors: %d. Rule not added.\n", filePath.c_str(), compile_errors);
            }
        }
    }
}
