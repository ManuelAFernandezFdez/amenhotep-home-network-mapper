# Amenhotep — Specification (short version)

Full version: [SPECIFICATION.md](SPECIFICATION.md)

## What it is
A desktop tool that finds every device on your home network, works out what each one is, lets you say where in the house it sits, and shows it all as a list, a network map and a 3D model of your house. It runs on your own computer. Nothing goes to the cloud.

*Amenhotep = Appliance Mapping & Enumeration of Network Hardware, Over Thread, Ethernet & Protocols.*
**Tagline:** "Nothing stays hidden from Amun." When every device is identified, Amun is satisfied ("23/23 devices known"). Unknown devices make him unsatisfied.

## What it should do
1. **Find devices**, wired and Wi-Fi, with their IP and MAC address.
2. **Identify them:** vendor, operating system (Linux, Windows, iOS…), device type and hardware model. Each answer comes with how sure the tool is and why.
3. **Recognise smart-home gear:** HomeKit accessories, plus Matter and Thread devices where possible.
4. **Show the wiring:** switches and Wi-Fi repeaters are devices too, with the devices that hang off them.
5. **Place devices** in a zone (floor, garden, veranda, roaming) and a room (kitchen, bedrooms…).
6. **Show a 3D house** from a plain text file you can edit by hand.
7. **Remember your edits.** What you type always wins over what a scan guesses.

## What it will not do
Capture traffic, hunt for vulnerabilities, control your devices, scan networks that are not yours, or sync to the cloud.

## Places in the house
- **Zones:** ground floor, first floor, second floor, garden, veranda, roaming.
- **Rooms:** kitchen and living room (ground), main, secondary and third bedroom (first), second-floor bedroom.
- A device is either **fixed** (has a place, never moved automatically) or **roaming** (a phone that moves around). A phone used as a bedside clock is pinned as *fixed*.

## Key scenarios
- Run a scan and see what is new or missing.
- Open a device, see what the tool thinks and why, and correct it.
- Pin a bedside-clock phone to the main bedroom.
- See which switch port or repeater a device uses.
- Click a room in 3D, drag a device, save. Edit the house file by hand and reload.

## Main requirements, in plain words
- **Discovery:** ping/ARP sweeps, port and service scans, operating-system fingerprinting, vendor lookup from the MAC address, devices announcing themselves (mDNS, UPnP), asking silent devices for their name. Scans run in the background and can be cancelled.
- **Presence:** a light check every 15–30 minutes records who is online, so devices that are off during a big scan are caught later. Only new or unidentified devices get a full probe.
- **Identification:** best evidence wins. HomeKit and Apple model strings are the most trusted, then UPnP, then nmap, then port patterns and the vendor.
- **Topology:** you link devices to switches or repeaters by hand, because your TP-Link switches and Ziggo repeaters report nothing. The router's client list may add hints.
- **3D:** floors stacked, rooms extruded from outlines, devices as markers, floor isolation, export to glTF.
- **Data:** one SQLite file for devices and history; the house shape in a JSON file.
- **Limits:** Linux first; up to about 500 devices; the GUI never blocks; no root needed for the GUI.

## Not possible on the network
The room names in Apple Home are not broadcast, so Amenhotep cannot read them. You assign rooms yourself.

## v1.0 is done when
A scan lists at least 95% of your devices; every device shows IP, MAC and vendor with evidence; HomeKit accessories show model and category; switches and both repeaters appear with children; areas survive rescans and IP changes; the 3D view opens, saves and reloads edits; the tests pass.
