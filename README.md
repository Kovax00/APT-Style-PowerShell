# APT-Style-PowerShell
**Proof of Concept** que replica la técnica de evasión avanzada utilizada por **APT35 (Charming Kitten)** en su backdoor "PowerLess" (2021-2022).
## Descripción Técnica

Este proyecto demuestra la ejecución de comandos PowerShell sin iniciar el proceso `powershell.exe`, utilizando directamente la API de .NET `System.Management.Automation.dll` mediante código C++/CLI.

### API Utilizada

**Namespace principal:**
```csharp
System.Management.Automation
```

**Componentes clave:**
- `PowerShell.Create()` - Inicializa el runspace de PowerShell
- `AddScript()` - Agrega comandos al pipeline
- `Invoke()` - Ejecuta el pipeline
- `Commands.Clear()` - Limpia el pipeline después de cada ejecución
- `Streams.Error` - Manejo de errores de PowerShell
- `Streams.Information/Warning/Verbose/Debug` - Streams de salida

### DLL Requerida
```
Assembly: System.Management.Automation.dll
Location: C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\
Version: Compatible con .NET Framework 4.x+
```

El código carga dinámicamente esta DLL desde el GAC (Global Assembly Cache) sin requerir referencias estáticas en tiempo de compilación.

## Diferencias con PowerShell Convencional

| Aspecto | powershell.exe | Este PoC |
|---------|---------------|----------|
| Proceso ejecutado | `powershell.exe` | Binario custom (ej: `MyApp.exe`) |
| Detección por nombre de proceso | Trivial | Requiere análisis de DLLs cargadas |
| Application Whitelisting bypass | No | Sí (si el binario está permitido) |
| Logging de PowerShell | Sí | Sí (aún genera logs si está habilitado) |
| AMSI scanning | Sí | Sí (puede ser bypasseado) |
| Firma digital | Microsoft | Depende del binario host |

## Contexto APT

### APT35 - PowerLess Backdoor (2021-2022)

**Atribución:** Islamic Revolutionary Guard Corps (IRGC), Irán

**Técnica documentada:**
- Loader: `PowerLessCLR.exe` (aplicación .NET C++)
- Decryptor: AES con clave hardcodeada
- Payload: PowerShell code ejecutado en contexto .NET
- Particularidad: **NO spawns proceso powershell.exe**

**Descubierto por:** Cybereason Nocturnus Team (Febrero 2022)

**MITRE ATT&CK Mapping:**
```
T1059.001 - Command and Scripting Interpreter: PowerShell
T1620    - Reflective Code Loading
T1027    - Obfuscated Files or Information
```

## Implementación Técnica

### Flujo de Ejecución
```
1. Aplicación C++/CLI inicia
   └─> Carga System.Management.Automation.dll desde GAC
       └─> Crea instancia de PowerShell via Reflection
           └─> Configura STA thread (requerido para clipboard/UI)
               └─> Loop interactivo
                   ├─> AddScript(comando_usuario)
                   ├─> Invoke()
                   ├─> Procesa streams (output, error, warning, etc.)
                   └─> Commands.Clear() (CRÍTICO para evitar estado corrupto)
```

### Manejo de Errores

El código implementa limpieza del pipeline en bloques catch para prevenir loops infinitos cuando hay errores de parsing (ej: comillas sin cerrar):
```cpp
catch (TargetInvocationException^ tie)
{
    clearCommands->Invoke(commands, nullptr);  // Limpieza del pipeline
    errorStream->Clear();                       // Vaciar streams
    // ... limpieza de otros streams
}
```

Sin esta limpieza, errores de sintaxis dejan el pipeline en estado inconsistente, causando que todos los comandos subsecuentes fallen.

## Compilación

### Requisitos

- Windows 10/11
- Visual Studio 2019 o superior
- Componente "C++/CLI support for v142+ build tools"
- .NET Framework 4.x o superior

### Proceso de Compilación

**Opción 1: Línea de comandos**
```bash
cl /clr API-powershell-aptComand.cpp
```

**Opción 2: Visual Studio**
1. Crear nuevo proyecto: "CLR Console App (.NET Framework)"
2. Pegar el código fuente
3. Compilar: `Ctrl+Shift+B`

### Notas Importantes

- **NO** usar `/EHsc` con `/clr` (son incompatibles)
- El flag `/clr` es obligatorio para habilitar extensiones C++/CLI
- El proyecto requiere .NET Framework, no .NET Core/5+

## Uso
```bash
# Ejecutar el binario compilado
API-powershell-aptComand.exe

# Ejemplo de sesión
[NTPowerShell]
[OK] In-Memory

PS C:\Users\user> Get-Process | Where-Object {$_.CPU -gt 100}
PS C:\Users\user> whoami /priv
PS C:\Users\user> Get-ChildItem -Recurse -Filter *.txt
PS C:\Users\user> exit
```

## Detección

### SIGMA Rule: System.Management.Automation.dll cargada por proceso no-PowerShell
```yaml
title: PowerShell Core DLL Loaded By Non PowerShell Process
id: 092bc4b9-3d1d-43b4-a6b4-8c8acd83522f
status: test
description: Detecta carga de System.Management.Automation.dll por procesos que no son powershell.exe
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\System.Management.Automation.dll'
    filter:
        Image|endswith:
            - '\powershell.exe'
            - '\powershell_ise.exe'
    condition: selection and not filter
falsepositives:
    - Aplicaciones legítimas que usan PowerShell API
    - Scripts de automatización empresarial
level: medium
tags:
    - attack.t1059.001
    - attack.execution
```

### Sysmon Event ID 7 (ImageLoad)

Monitorear eventos de carga de DLL que incluyan:
```xml
7
System.Management.Automation.dll
C:\Path\To\Suspicious.exe
```

### Contramedidas Recomendadas

**PowerShell Logging:**
```powershell
# Habilitar Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                 -Name "EnableScriptBlockLogging" -Value 1

# Habilitar Module Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
                 -Name "EnableModuleLogging" -Value 1

# Habilitar Transcription
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
                 -Name "EnableTranscripting" -Value 1
```

**Application Whitelisting:**
- Implementar políticas estrictas de ejecución de binarios
- Monitorear carga de DLLs sensibles (no solo ejecución de procesos)
- Utilizar EDR con capacidades de behavioral detection

**Constrained Language Mode:**
```powershell
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
```

Nota: Este modo puede ser bypasseado en ciertos escenarios mediante técnicas de reflective loading.

## Disclaimer Legal

**SOLO PARA FINES EDUCATIVOS Y ETHICAL HACKING**

Este proyecto es un Proof of Concept desarrollado exclusivamente para:

- Investigación en ciberseguridad
- Ejercicios de Red Team / Purple Team autorizados
- Entrenamiento de equipos defensivos
- Análisis de técnicas APT documentadas

**Prohibiciones:**
- Uso en sistemas sin autorización explícita
- Distribución con fines maliciosos
- Implementación en entornos de producción sin consentimiento

El autor no se hace responsable del uso indebido de esta herramienta. El mal uso puede constituir delito bajo las leyes de ciberseguridad aplicables en su jurisdicción.

## Referencias

- Cybereason (2022): "PowerLess Trojan: Iranian APT Phosphorus Adds New PowerShell Backdoor for Espionage"
  https://www.cybereason.com/blog/powerless-trojan-iranian-apt-phosphorus-adds-new-powershell-backdoor-for-espionage

- MITRE ATT&CK: T1059.001 - Command and Scripting Interpreter: PowerShell
  https://attack.mitre.org/techniques/T1059/001/

- Microsoft Docs: System.Management.Automation Namespace
  https://docs.microsoft.com/en-us/dotnet/api/system.management.automation

- SIGMA Rules Repository
  https://github.com/SigmaHQ/sigma

## Licencia

MIT License - Ver archivo LICENSE para detalles completos.

---

**Desarrollado con fines educativos** | **APT Technique Research** | **Enero 2026**
