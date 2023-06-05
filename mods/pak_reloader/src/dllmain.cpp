#include <string>
#include <stdio.h>

#include <GUI/GUITab.hpp>
#include <Mod/CppUserModBase.hpp>
#include <UE4SSProgram.hpp>
#include <PakReloader.hpp>

class ModTab : public GUI::GUITab
{
private:
    RC::GUI::PakReloader::PakReloader m_pak_reloader{};

public:
    ModTab() : RC::GUI::GUITab()
    {
        TabName = L"Pak Reloader";
    }

    auto render() -> void override
    {
        m_pak_reloader.render();
    }
};

class PakReloaderMod : public RC::CppUserModBase
{
private:
    std::shared_ptr<ModTab> m_mod_tab{};

public:
    PakReloaderMod() : CppUserModBase()
    {
        ModName = STR("PakReloader");
        ModVersion = STR("1.0");
        ModDescription = STR("Tool for mounting, unmount, and reloading paks");
        ModAuthors = STR("truman");

        UE4SS_ENABLE_IMGUI()

        m_mod_tab = std::make_shared<ModTab>();
        UE4SSProgram::get_program().add_gui_tab(m_mod_tab);
    }

    ~PakReloaderMod()
    {
        if (m_mod_tab)
            UE4SSProgram::get_program().remove_gui_tab(m_mod_tab);
    }
    auto on_program_start() -> void override { }
    auto on_update() -> void override { }
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

