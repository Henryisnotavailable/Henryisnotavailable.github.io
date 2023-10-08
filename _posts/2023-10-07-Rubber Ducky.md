# Make your own rubber ducky

---

If you don't know, a rubber ducky is essentially a pre-programmed USB keyboard that types at a super fast speed. Oh, it also looks like a harmless flash drive ;)


You can find the official rubber ducky from the Hak5 [website](https://shop.hak5.org/products/usb-rubber-ducky). At a price of ~$80 it's not cheap...

Thankfully you can make your own for ~$2.50! All it requires is 
- An [Attiny85](https://www.amazon.co.uk/attiny85/s?k=attiny85)
- Some [drivers](https://github.com/digistump/DigistumpArduino/releases)
- The [Arduino IDE](https://www.arduino.cc/en/software)
- A Windows OS (I haven't tested on Linux)

To install the drivers just extract the zip, and run either DPinst64 (for x64 systems) or DPinst (for x32 systems).

To setup the Arduino IDE, open it up and go to: 
- File -> Preferences -> Additional Boards Manager URLs and enter `https://digistump.com/package_digistump_index.json`
![Arduino](https://raw.githubusercontent.com/Henryisnotavailable/Henryisnotavailable.github.io/main/assets/images/Capture.PNG)

![Additonal Board URLs](https://raw.githubusercontent.com/Henryisnotavailable/Henryisnotavailable.github.io/main/assets/images/Additional_Board_Manager.PNG)

![Digistump Index](https://raw.githubusercontent.com/Henryisnotavailable/Henryisnotavailable.github.io/main/assets/images/digistump_index.PNG)

- Tools -> Board -> Boards Manager and enter digispark and select `Digistump AVR Boards by Digistump` to install it

![Boards Manager](https://raw.githubusercontent.com/Henryisnotavailable/Henryisnotavailable.github.io/main/assets/images/boards_manager.PNG)

![Digispark Board](https://raw.githubusercontent.com/Henryisnotavailable/Henryisnotavailable.github.io/main/assets/images/digistump_board.PNG)

- Tools -> and Select "Board Digispark (Default - 16.5mhz)"

![Select Digispark](https://raw.githubusercontent.com/Henryisnotavailable/Henryisnotavailable.github.io/main/assets/images/Select_Board.PNG)
