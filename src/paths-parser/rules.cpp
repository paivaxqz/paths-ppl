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

    // 1. TODO: placeholder - preencher com as strings novas. Mantido compilando (condition false).
    addGenericRule("Specifics B", R"YR(
rule cheat
{
  meta:
    description = "Specifics B - TODO: refazer strings"
  strings:
    $todo = "__PATHS_TODO_PLACEHOLDER__"
  condition:
    false and $todo
}
)YR");

    // 2 + 7 + 8 unificadas: entropy do arquivo inteiro OU de alguma secao PE
    addGenericRule("entropy", R"YR(
import "pe"
import "math"

rule entropy
{
  meta:
    description = "PE com entropy alta (arquivo >= 7.0 ou secao > 7.0)"
  condition:
    uint16(0) == 0x5A4D and pe.is_pe and filesize > 4KB and
    (
      math.entropy(0, filesize) >= 7.0 or
      for any s in pe.sections : (
        s.raw_data_size > 1024 and
        s.name != ".rsrc" and
        math.entropy(s.raw_data_offset, s.raw_data_size) > 7.0
      )
    )
}
)YR");

    // 3. Packers
    addGenericRule("murielson", R"YR(
import "pe"

rule empacotamentoruim
{
  meta:
    description = "PE empacotado (UPX, MPRESS, ASPack, Themida, VMProtect, Enigma, PECompact, Obsidium...)"
  strings:
    $upx_magic = "UPX!"
    $mpress    = "MPRESS"
    $aspack    = "ASPack" nocase
    $pecompact = "PECompact2"
    $enigma    = "Enigma protector" nocase
    $obsidium  = "Obsidium" nocase
  condition:
    uint16(0) == 0x5A4D and pe.is_pe and
    (
      for any s in pe.sections : (
        s.name == "UPX0" or s.name == "UPX1" or s.name == "UPX2" or s.name == ".UPX" or
        s.name == ".MPRESS1" or s.name == ".MPRESS2" or
        s.name == ".aspack" or s.name == ".adata" or
        s.name == ".themida" or s.name == ".winlice" or s.name == ".boot" or
        s.name == ".vmp0" or s.name == ".vmp1" or s.name == ".vmp2" or
        s.name == ".enigma1" or s.name == ".enigma2" or
        s.name == "PEC2" or s.name == "PEC2TO" or s.name == "pec1" or
        s.name == ".obsidium"
      ) or
      $upx_magic in (0..0x1000) or
      $mpress in (0..0x1000) or
      any of ($aspack, $pecompact, $enigma, $obsidium) in (0..0x2000)
    )
}
)YR");

    // 4. Obfuscators .NET (1 marcador forte OU 2 fracos)
    addGenericRule("Obfuscated__FakeSignatures", R"YR(
import "pe"

rule Obfuscated__FakeSignatures
{
  meta:
    description = "Assembly .NET ofuscado"
  strings:
    $s1  = "ConfusedByAttribute" ascii wide
    $s2  = "Confuser.Core" ascii wide
    $s3  = "ConfuserEx v" ascii wide
    $s4  = "DotfuscatorAttribute" ascii wide
    $s5  = "SmartAssembly.Attributes" ascii wide
    $s6  = "PoweredByAttribute" ascii wide
    $s7  = "BabelObfuscatorAttribute" ascii wide
    $s8  = "Xenocode.Client.Attributes" ascii wide
    $s9  = "CryptoObfuscator" ascii wide
    $s10 = "ObfuscatedByGoliath" ascii wide
    $s11 = "Eazfuscator" ascii wide
    $s12 = "<PrivateImplementationDetails>{" ascii wide
    $s13 = "KoiVM" ascii wide
    $s14 = "Inx .NET Obfuscator" ascii wide
    $s15 = "ObfuscatedByAgileDotNet" ascii wide
    $s16 = "AgileDotNetRT" ascii wide
    $s17 = "__DNGuard" ascii wide
    $s18 = "MaxtoCode" ascii wide
    $s19 = "Spices.Net" ascii wide
    $s20 = "YanoAttribute" ascii wide
    $s21 = "NETGuard" ascii wide
    $s22 = "BitMono" ascii wide
    $w1  = "costura." ascii wide nocase
    $w2  = "ProcessedByFody" ascii wide
    $w3  = "AssemblyLoader" ascii wide
    $w4  = "SuppressIldasmAttribute" ascii wide
    $w5  = "VMProtect" ascii wide
    $w6  = ".NET Reactor" ascii wide
    $w7  = "Babel" ascii wide
  condition:
    uint16(0) == 0x5A4D and pe.is_pe and
    (pe.imports("mscoree.dll", "_CorExeMain") or pe.imports("mscoree.dll", "_CorDllMain") or
     pe.data_directories[14].virtual_address != 0) and
    (any of ($s*) or 2 of ($w*))
}
)YR");

    // 5. AnyDesk fake em .NET
    addGenericRule("fake_anydesk_dotnet", R"YR(
import "pe"
rule fake_anydesk_dotnet {
    strings:
        $anydesk = "AnyDesk" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and pe.is_pe and $anydesk and
        (pe.imports("mscoree.dll", "_CorExeMain") or pe.imports("mscoree.dll", "_CorDllMain"))
})YR");

    // 6. AnyDesk + features de cheat
    addGenericRule("anydesk_cheat_bruxomem", R"YR(
rule anydesk_cheat_bruxomem {
    strings:
        $anydesk = "AnyDesk" nocase ascii wide
        $fody = "ProcessedByFody" ascii wide
        $bruxo = "BruxoMem" nocase ascii wide
        $aimbot = "Aimboton" nocase ascii wide
        $aobscan = "AoBScan" nocase ascii wide
        $camhack = "Camera Hack" nocase ascii wide
        $galib = "Red.GALIB" nocase ascii wide
        $antivm1 = "VBoxMouse.sys" nocase ascii wide
        $antivm2 = "VMware Tools" nocase ascii wide
        $harmony = "0Harmony.dll" nocase ascii wide
        $obfuscator = "Inx .NET Obfuscator" ascii wide
        $hdplayer = "HD-Player.exe" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and $anydesk and
        2 of ($fody, $bruxo, $aimbot, $aobscan, $camhack, $galib, $antivm*, $harmony, $obfuscator, $hdplayer)
})YR");

    // 9. Frameworks de hook / injecao / drivers vulneraveis
    addGenericRule("cheat_frameworks", R"YR(
import "pe"

rule cheat_frameworks
{
  meta:
    description = "Hook/injecao/mapper (alta) - ImGui sozinho NAO cai aqui"
  strings:
    $imgui1 = "ImGui" ascii
    $imgui2 = "imgui.ini" ascii
    $imgui3 = "##OverlayWindow" ascii
    $imgui4 = "ImGui_ImplDX11_" ascii
    $imgui5 = "ImGui_ImplWin32_" ascii

    $hk1 = "MH_CreateHook" ascii
    $hk2 = "MH_EnableHook" ascii
    $hk3 = "MH_Initialize" ascii
    $hk4 = "kiero::" ascii
    $hk5 = "kiero" ascii fullword
    $hk6 = "DetourAttach" ascii
    $hk7 = "DetourTransactionBegin" ascii
    $hk8 = "PLH::" ascii
    $hk9 = "safetyhook" ascii
    $hk10 = "hkPresent" ascii
    $hk11 = "oPresent" ascii fullword
    $hk12 = "hkEndScene" ascii
    $hk13 = "hkResizeBuffers" ascii

    $drv1 = "kdmapper" nocase ascii wide
    $drv2 = "drvmap" nocase ascii wide
    $drv3 = "iqvw64e.sys" nocase ascii wide
    $drv4 = "gdrv.sys" nocase ascii wide
    $drv5 = "mhyprot2.sys" nocase ascii wide
    $drv6 = "RTCore64.sys" nocase ascii wide
    $drv7 = "dbutil_2_3.sys" nocase ascii wide
    $drv8 = "AsrDrv10" nocase ascii wide
    $drv9 = "WinRing0x64.sys" nocase ascii wide
    $drv10 = "capcom.sys" nocase ascii wide
    $drv11 = "MapDriver" ascii wide
    $drv12 = "isDriverMapped" ascii wide

    $inj1 = "VirtualAllocEx" ascii
    $inj2 = "WriteProcessMemory" ascii
    $inj3 = "NtCreateThreadEx" ascii
    $inj4 = "CreateRemoteThread" ascii
    $inj5 = "LdrLoadDll" ascii
    $inj6 = "manualmap" nocase ascii wide
    $inj7 = "ManualMapDll" nocase ascii wide
  condition:
    uint16(0) == 0x5A4D and pe.is_pe and
    (
      2 of ($drv*) or
      ($drv1 or $drv2 or $drv11 or $drv12) or
      (2 of ($imgui*) and (any of ($hk*) or 2 of ($inj*))) or
      (2 of ($hk*) and 2 of ($inj*)) or
      ($inj1 and $inj2 and ($inj3 or $inj4) and ($inj6 or $inj7))
    )
}
)YR");

    // 10. Free Fire / emulador
    addGenericRule("freefire_cheat_bypass", R"YR(
rule freefire_cheat_bypass
{
  meta:
    description = "Cheat Free Fire / emulador"
  strings:
    $emu1 = "HD-Player.exe" nocase ascii wide
    $emu2 = "HD-Player" nocase ascii wide
    $emu3 = "BlueStacks" nocase ascii wide
    $emu4 = "MSI App Player" nocase ascii wide
    $emu5 = "LdVBoxHeadless" nocase ascii wide
    $emu6 = "dnplayer.exe" nocase ascii wide
    $emu7 = "MEmuHeadless" nocase ascii wide
    $emu8 = "AndroidProcess.exe" nocase ascii wide

    $pkg1 = "com.dts.freefireth" nocase ascii wide
    $pkg2 = "com.dts.freefiremax" nocase ascii wide
    $pkg3 = "libil2cpp.so" nocase ascii wide
    $pkg4 = "libunity.so" nocase ascii wide

    $feat1  = "aimbot" nocase ascii wide
    $feat2  = "aimlock" nocase ascii wide
    $feat3  = "headshot" nocase ascii wide
    $feat4  = "wallhack" nocase ascii wide
    $feat5  = "esp line" nocase ascii wide
    $feat6  = "esp box" nocase ascii wide
    $feat7  = "chams" nocase ascii wide fullword
    $feat8  = "antena" nocase ascii wide fullword
    $feat9  = "holograma" nocase ascii wide
    $feat10 = "bala magica" nocase ascii wide
    $feat11 = "bala m\xc3\xa1gica" nocase ascii
    $feat12 = "magic bullet" nocase ascii wide
    $feat13 = "no recoil" nocase ascii wide
    $feat14 = "speed hack" nocase ascii wide
    $feat15 = "telekill" nocase ascii wide
    $feat16 = "fly hack" nocase ascii wide
    $feat17 = "cam hack" nocase ascii wide
    $feat18 = "camera hack" nocase ascii wide
    $feat19 = "AoBScan" nocase ascii wide
    $feat20 = "BruxoMem" nocase ascii wide
    $feat21 = "Aimboton" nocase ascii wide
    $feat22 = "falconmem" nocase ascii wide
    $feat23 = "Memory.dll" nocase ascii wide
    $feat24 = "bypass emulador" nocase ascii wide
    $feat25 = "bypass ff" nocase ascii wide
    $feat26 = "auxilio de mira" nocase ascii wide
    $feat27 = "sensi ff" nocase ascii wide
    $feat28 = "mod menu" nocase ascii wide
    $feat29 = "fake device" nocase ascii wide

    $api1 = "VirtualQueryEx" ascii
    $api2 = "ReadProcessMemory" ascii
    $api3 = "WriteProcessMemory" ascii
  condition:
    (any of ($emu*) and any of ($feat*)) or
    (any of ($pkg*) and any of ($feat*)) or
    (any of ($emu*) and $api1 and ($api2 or $api3) and any of ($pkg*)) or
    3 of ($feat*)
}
)YR");

    // NOVA: XISFPS / XFPS
    addGenericRule("X1", R"YR(
rule X1
{
  meta:
    description = "IOCs XISFPS/XFPS (painel ESP/aimbot, DriverCom, SystemX.evtx)"
  strings:
    $st1 = "XISFPS" nocase ascii wide
    $st2 = "SystemX.evtx" nocase ascii wide
    $st3 = "zimo.br" nocase ascii wide
    $st4 = "99ECF177DA86CB646CDF9A7910275CDC07A42AA3" nocase ascii wide
    $st5 = { 99 EC F1 77 DA 86 CB 64 6C DF 9A 79 10 27 5C DC 07 A4 2A A3 }
    $drvcom = "DriverCom" ascii wide
    $api1 = "/api/espdata" ascii wide
    $api2 = "/api/aimbotswap" ascii wide
    $api3 = "/api/reloadaimbind" ascii wide
    $api4 = "/api/disable_all" ascii wide
    $w1 = "esp_started" ascii wide
    $w2 = "offsets_ok" ascii wide
    $w3 = "destruct_result" ascii wide
    $w4 = "windowshome" ascii wide
  condition:
    any of ($st*) or
    ($drvcom and any of ($api*)) or
    2 of ($api*, $w*)
}
)YR");

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
