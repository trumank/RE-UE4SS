#include <string>

#include <GUI/GUITab.hpp>
#include <Mod/CppUserModBase.hpp>
#include <UE4SSProgram.hpp>
#include <PakReloader.hpp>

class PakReloaderMod : public RC::CppUserModBase
{
private:
    RC::GUI::PakReloader::PakReloader m_pak_reloader{};

public:
    PakReloaderMod() : CppUserModBase()
    {
        ModName = STR("PakReloader");
        ModVersion = STR("1.0");
        ModDescription = STR("Tool for mounting, unmount, and reloading paks");
        ModAuthors = STR("truman");

        UE4SS_ENABLE_IMGUI()

        register_tab(STR("Pak Reloader"), [](CppUserModBase* mod) { dynamic_cast<PakReloaderMod*>(mod)->m_pak_reloader.render(); });
    }

    ~PakReloaderMod() override = default;
};

#define MY_AWESOME_MOD_API __declspec(dllexport)
extern "C"
{
    MY_AWESOME_MOD_API RC::CppUserModBase* start_mod()
    {
        return new PakReloaderMod();
    }

    MY_AWESOME_MOD_API void uninstall_mod(RC::CppUserModBase* mod)
    {
        delete mod;
    }
}

