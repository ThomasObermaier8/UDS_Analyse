#!/usr/bin/env python3
"""UDS Analyzer GUI with exhaustive ISO-14229 code-space database view."""

from __future__ import annotations

import re
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk

HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")

# ISO-14229 standard service names (known assignments)
ISO_SERVICE_NAMES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x24: "ReadScalingDataByIdentifier",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x29: "Authentication",
    0x2A: "ReadDataByPeriodicIdentifier",
    0x2C: "DynamicallyDefineDataIdentifier",
    0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x38: "RequestFileTransfer",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x83: "AccessTimingParameter",
    0x84: "SecuredDataTransmission",
    0x85: "ControlDTCSetting",
    0x86: "ResponseOnEvent",
    0x87: "LinkControl",
}

SERVICE_SUBFUNCTIONS = {
    0x10: {0x00: "ISOSAEReserved", 0x01: "defaultSession", 0x02: "programmingSession", 0x03: "extendedDiagnosticSession", 0x04: "safetySystemDiagnosticSession"},
    0x11: {0x01: "hardReset", 0x02: "keyOffOnReset", 0x03: "softReset", 0x04: "enableRapidPowerShutDown", 0x05: "disableRapidPowerShutDown"},
    0x19: {0x01: "reportNumberOfDTCByStatusMask", 0x02: "reportDTCByStatusMask", 0x03: "reportDTCSnapshotIdentification", 0x04: "reportDTCSnapshotRecordByDTCNumber", 0x05: "reportDTCSnapshotRecordByRecordNumber", 0x06: "reportDTCExtDataRecordByDTCNumber", 0x07: "reportNumberOfDTCBySeverityMaskRecord", 0x08: "reportDTCBySeverityMaskRecord", 0x09: "reportSeverityInformationOfDTC", 0x0A: "reportSupportedDTC", 0x0B: "reportFirstTestFailedDTC", 0x0C: "reportFirstConfirmedDTC", 0x0D: "reportMostRecentTestFailedDTC", 0x0E: "reportMostRecentConfirmedDTC", 0x0F: "reportMirrorMemoryDTCByStatusMask", 0x10: "reportMirrorMemoryDTCExtDataRecordByDTCNumber", 0x11: "reportNumberOfMirrorMemoryDTCByStatusMask", 0x12: "reportNumberOfEmissionsRelatedOBDDTCByStatusMask", 0x13: "reportEmissionsRelatedOBDDTCByStatusMask", 0x14: "reportDTCFaultDetectionCounter", 0x15: "reportDTCWithPermanentStatus"},
    0x28: {0x00: "enableRxAndTx", 0x01: "enableRxAndDisableTx", 0x02: "disableRxAndEnableTx", 0x03: "disableRxAndTx"},
    0x2C: {0x01: "defineByIdentifier", 0x02: "defineByMemoryAddress", 0x03: "clearDynamicallyDefinedDataIdentifier"},
    0x2F: {0x00: "returnControlToECU", 0x01: "resetToDefault", 0x02: "freezeCurrentState", 0x03: "shortTermAdjustment"},
    0x31: {0x01: "startRoutine", 0x02: "stopRoutine", 0x03: "requestRoutineResults"},
    0x3E: {0x00: "zeroSubFunction"},
    0x85: {0x01: "on", 0x02: "off"},
}

ISO_NRC_NAMES = {
    0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported", 0x13: "incorrectMessageLengthOrInvalidFormat", 0x14: "responseTooLong", 0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect", 0x24: "requestSequenceError", 0x25: "noResponseFromSubnetComponent", 0x26: "failurePreventsExecutionOfRequestedAction", 0x31: "requestOutOfRange", 0x33: "securityAccessDenied", 0x34: "authenticationRequired", 0x35: "invalidKey", 0x36: "exceedNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired", 0x38: "secureDataTransmissionRequired", 0x39: "secureDataTransmissionNotAllowed", 0x3A: "secureDataVerificationFailed", 0x50: "certificateVerificationFailedInvalidTimePeriod", 0x51: "certificateVerificationFailedInvalidSignature", 0x52: "certificateVerificationFailedInvalidChainOfTrust", 0x53: "certificateVerificationFailedInvalidType", 0x54: "certificateVerificationFailedInvalidFormat", 0x55: "certificateVerificationFailedInvalidContent", 0x56: "certificateVerificationFailedInvalidScope", 0x57: "certificateVerificationFailedInvalidCertificate", 0x58: "ownershipVerificationFailed", 0x59: "challengeCalculationFailed", 0x5A: "settingAccessRightsFailed", 0x5B: "sessionKeyCreationOrDerivationFailed", 0x5C: "configurationDataUsageFailed", 0x5D: "deAuthenticationFailed", 0x70: "uploadDownloadNotAccepted", 0x71: "transferDataSuspended", 0x72: "generalProgrammingFailure", 0x73: "wrongBlockSequenceCounter", 0x78: "requestCorrectlyReceivedResponsePending", 0x7E: "subFunctionNotSupportedInActiveSession", 0x7F: "serviceNotSupportedInActiveSession", 0x81: "rpmTooHigh", 0x82: "rpmTooLow", 0x83: "engineIsRunning", 0x84: "engineIsNotRunning", 0x85: "engineRunTimeTooLow", 0x86: "temperatureTooHigh", 0x87: "temperatureTooLow", 0x88: "vehicleSpeedTooHigh", 0x89: "vehicleSpeedTooLow", 0x8A: "throttlePedalTooHigh", 0x8B: "throttlePedalTooLow", 0x8C: "transmissionRangeNotInNeutral", 0x8D: "transmissionRangeNotInGear", 0x8F: "brakeSwitchNotClosed", 0x90: "shifterLeverNotInPark", 0x91: "torqueConverterClutchLocked", 0x92: "voltageTooHigh", 0x93: "voltageTooLow", 0x94: "resourceTemporarilyNotAvailable",
}

DID_NOTES = {
    0xF186: "ActiveDiagnosticSession", 0xF187: "VehicleManufacturerSparePartNumber", 0xF188: "VehicleManufacturerECUSoftwareNumber", 0xF189: "VehicleManufacturerECUSoftwareVersionNumber", 0xF18A: "SystemSupplierIdentifier", 0xF18B: "ECUManufacturingDate", 0xF18C: "ECUSerialNumber", 0xF18D: "SupportedFunctionalUnits", 0xF18E: "VehicleManufacturerKitAssemblyPartNumber", 0xF190: "VehicleIdentificationNumber (VIN)", 0xF191: "VehicleManufacturerECUHardwareNumber", 0xF192: "SystemSupplierECUHardwareNumber", 0xF193: "SystemSupplierECUHardwareVersionNumber", 0xF194: "SystemSupplierECUSoftwareNumber", 0xF195: "SystemSupplierECUSoftwareVersionNumber", 0xF196: "ExhaustRegulationOrTypeApprovalNumber", 0xF197: "SystemNameOrEngineType", 0xF198: "RepairShopCodeOrTesterSerialNumber", 0xF199: "ProgrammingDate", 0xF19A: "CalibrationRepairShopCodeOrCalibrationEquipmentSerialNumber", 0xF19B: "CalibrationDate", 0xF19C: "CalibrationEquipmentSoftwareNumber", 0xF19D: "ECUInstallationDate", 0xF19E: "ODXFileIdentifier", 0xF19F: "Entity",
}


def build_full_services() -> dict[int, dict]:
    services: dict[int, dict] = {}
    for sid in range(0x00, 0x100):
        entry = {
            "name": ISO_SERVICE_NAMES.get(sid, "ISOReservedOrNotAssigned"),
            "status": "standardized" if sid in ISO_SERVICE_NAMES else "reserved/not-assigned",
            "subfunctions": SERVICE_SUBFUNCTIONS.get(sid, {}),
        }
        services[sid] = entry
    return services


def build_full_nrc() -> dict[int, str]:
    nrc: dict[int, str] = {}
    for code in range(0x00, 0x100):
        nrc[code] = ISO_NRC_NAMES.get(code, "ISOReservedOrManufacturerSpecific")
    return nrc


UDS_DATABASE = {
    "services": build_full_services(),
    "negative_response_codes": build_full_nrc(),
    "did_notes": DID_NOTES,
}


@dataclass
class ServiceInfo:
    sid: int
    name: str


def get_service_info(sid: int) -> ServiceInfo:
    return ServiceInfo(sid=sid, name=UDS_DATABASE["services"].get(sid, {"name": f"UnknownService(0x{sid:02X})"})["name"])


def get_subfunction_name(sid: int, sub: int) -> str:
    return UDS_DATABASE["services"].get(sid, {}).get("subfunctions", {}).get(sub, "unknownSubFunction")


def get_did_name(did: int) -> str:
    known = UDS_DATABASE["did_notes"].get(did)
    if known:
        return known
    if 0xF180 <= did <= 0xF19F:
        return "ISO-14229 standardisierter VehicleIdentificationData DID"
    if 0xF1A0 <= did <= 0xF1EF:
        return "ISO-14229 reservierter DID-Bereich"
    if 0xF1F0 <= did <= 0xF1FF:
        return "Herstellerspezifischer Identifikations-DID"
    if 0xF200 <= did <= 0xF2FF:
        return "Periodischer/erweiterter DID-Bereich"
    if 0xF300 <= did <= 0xF3FF:
        return "OBD-/Emissionsbezogener DID-Bereich"
    if 0xF400 <= did <= 0xFEFF:
        return "OEM-spezifischer DID-Bereich"
    if 0xFF00 <= did <= 0xFFFF:
        return "Netzwerk-/Sitzungsspezifischer DID-Bereich"
    return "Allgemeiner DID (fahrzeug- oder OEM-spezifisch)"


def bytes_to_ascii(byte_values: list[int]) -> str:
    if not byte_values:
        return ""
    chars, printable = [], 0
    for value in byte_values:
        if 32 <= value <= 126:
            chars.append(chr(value)); printable += 1
        elif value in (9, 10, 13):
            chars.append(" "); printable += 1
        else:
            chars.append(".")
    return "".join(chars) if printable / len(byte_values) >= 0.6 else ""


def build_database_entries() -> list[str]:
    entries: list[str] = []
    for sid, service in sorted(UDS_DATABASE["services"].items()):
        entries.append(f"SERVICE 0x{sid:02X} {service['name']} [{service['status']}]")
        for sub, sub_name in sorted(service.get("subfunctions", {}).items()):
            entries.append(f"  SUB 0x{sub:02X} {sub_name}")
    for nrc, name in sorted(UDS_DATABASE["negative_response_codes"].items()):
        entries.append(f"NRC 0x{nrc:02X} {name}")
    for did, name in sorted(UDS_DATABASE["did_notes"].items()):
        entries.append(f"DID 0x{did:04X} {name}")
    entries.append("DID RANGE 0x0000-0xFFFF vollständig abgedeckt (bekannt + Bereichszuordnung)")
    return entries


def filter_database_entries(entries: list[str], query: str) -> list[str]:
    q = query.strip().lower()
    return entries if not q else [entry for entry in entries if q in entry.lower()]


def decode_payload(payload: list[int]) -> str:
    if not payload:
        return "Leere Payload"
    sid = payload[0]
    parts = [f"Raw: {' '.join(f'{b:02X}' for b in payload)}"]

    if sid == 0x7F:
        if len(payload) < 3:
            return " | ".join(parts + ["Typ: NegativeResponse (unvollständig)"])
        req_sid, nrc = payload[1], payload[2]
        parts.append(f"Typ: NegativeResponse auf {get_service_info(req_sid).name} (0x{req_sid:02X})")
        parts.append(f"NRC: {UDS_DATABASE['negative_response_codes'][nrc]} (0x{nrc:02X})")
        if len(payload) > 3:
            extra = payload[3:]
            parts.append(f"Zusatzdaten: {' '.join(f'{b:02X}' for b in extra)}")
            if (ascii_extra := bytes_to_ascii(extra)):
                parts.append(f"ASCII: {ascii_extra}")
        return " | ".join(parts)

    is_positive = sid >= 0x40
    base_sid = sid - 0x40 if is_positive else sid
    parts.append(f"Typ: {'PositiveResponse auf' if is_positive else 'Request'} {get_service_info(base_sid).name} (0x{base_sid:02X})")

    if len(payload) >= 2 and UDS_DATABASE["services"][base_sid].get("subfunctions"):
        parts.append(f"SubFunction: {get_subfunction_name(base_sid, payload[1])} (0x{payload[1]:02X})")
    if base_sid in (0x22, 0x2E) and len(payload) >= 3:
        did = (payload[1] << 8) | payload[2]
        parts.append(f"DID: 0x{did:04X} ({get_did_name(did)})")
        if len(payload) > 3 and (did_ascii := bytes_to_ascii(payload[3:])):
            parts.append(f"DID-ASCII: {did_ascii}")
    if base_sid == 0x27 and len(payload) >= 2:
        parts.append(f"SecurityLevel: 0x{payload[1]:02X} ({'RequestSeed' if payload[1] % 2 else 'SendKey'})")
    if base_sid == 0x31 and len(payload) >= 4:
        parts.append(f"RoutineIdentifier: 0x{((payload[2] << 8) | payload[3]):04X}")

    if len(payload) > 1:
        data = payload[1:]
        parts.append(f"Nutzdaten: {' '.join(f'{b:02X}' for b in data)}")
        if (ascii_data := bytes_to_ascii(data)):
            parts.append(f"ASCII: {ascii_data}")
    return " | ".join(parts)


def decode_text(raw_text: str) -> str:
    lines = []
    for idx, line in enumerate(raw_text.splitlines(), start=1):
        tokens = HEX_RE.findall(line)
        if tokens:
            lines.append(f"Zeile {idx}: {decode_payload([int(t, 16) for t in tokens])}")
    return "\n".join(lines) if lines else "Keine gültigen UDS-Bytes erkannt. Bitte Hex-Bytes wie z.B. '10 03' einfügen."


class UDSAnalyzerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("UDS Analyzer – Vollständige Datenbank")
        self.geometry("1100x760")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(3, weight=1)

        ttk.Label(self, text="UDS Kommunikation Decoder (ISO-14229 Vollabdeckung)", font=("Arial", 14, "bold")).grid(row=0, column=0, padx=10, pady=(10, 6), sticky="w")
        self.input_text = tk.Text(self, wrap="word", height=15)
        self.input_text.grid(row=1, column=0, padx=10, pady=6, sticky="nsew")

        button_bar = ttk.Frame(self)
        button_bar.grid(row=2, column=0, padx=10, pady=6, sticky="ew")
        for col in range(4):
            button_bar.columnconfigure(col, weight=1)

        ttk.Button(button_bar, text="Dekodieren", command=self.on_decode).grid(row=0, column=0, padx=4, sticky="ew")
        ttk.Button(button_bar, text="Leeren", command=self.on_clear).grid(row=0, column=1, padx=4, sticky="ew")
        ttk.Button(button_bar, text="Beispiel laden", command=self.load_example).grid(row=0, column=2, padx=4, sticky="ew")
        ttk.Button(button_bar, text="Datenbank anzeigen", command=self.open_database_viewer).grid(row=0, column=3, padx=4, sticky="ew")

        self.output_text = tk.Text(self, wrap="word", height=16, state="disabled")
        self.output_text.grid(row=3, column=0, padx=10, pady=(6, 10), sticky="nsew")

        self.db_window: tk.Toplevel | None = None
        self.db_search_var = tk.StringVar(value="")
        self.db_entries = build_database_entries()
        self.db_text: tk.Text | None = None
        self.load_example()

    def on_decode(self) -> None:
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", decode_text(self.input_text.get("1.0", "end")))
        self.output_text.config(state="disabled")

    def on_clear(self) -> None:
        self.input_text.delete("1.0", "end")
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.config(state="disabled")

    def load_example(self) -> None:
        sample = "7E0 8 10 03\n7E8 8 50 03 00 32 01 F4\n7E0 8 22 F1 90\n7E8 8 62 F1 90 57 56 57 5A\n7E8 8 7F 22 31\n31 01 FF 00 12 34\n"
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", sample)
        self.on_decode()

    def open_database_viewer(self) -> None:
        if self.db_window and self.db_window.winfo_exists():
            self.db_window.lift()
            self.db_window.focus_force()
            return
        self.db_window = tk.Toplevel(self)
        self.db_window.title("UDS Datenbank – ISO-14229 Suche")
        self.db_window.geometry("980x640")
        self.db_window.columnconfigure(0, weight=1)
        self.db_window.rowconfigure(2, weight=1)

        ttk.Label(self.db_window, text="Suche (SID/NRC/DID/Name):").grid(row=0, column=0, padx=10, pady=(10, 4), sticky="w")
        entry = ttk.Entry(self.db_window, textvariable=self.db_search_var)
        entry.grid(row=1, column=0, padx=10, pady=(0, 6), sticky="ew")
        entry.bind("<KeyRelease>", lambda _e: self.refresh_database_view())

        self.db_text = tk.Text(self.db_window, wrap="none")
        self.db_text.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.refresh_database_view()

    def refresh_database_view(self) -> None:
        if not self.db_text:
            return
        filtered = filter_database_entries(self.db_entries, self.db_search_var.get())
        self.db_text.config(state="normal")
        self.db_text.delete("1.0", "end")
        self.db_text.insert("1.0", "\n".join(filtered) if filtered else "Keine Einträge für die aktuelle Suche gefunden.")
        self.db_text.config(state="disabled")


if __name__ == "__main__":
    app = UDSAnalyzerApp()
    app.mainloop()
