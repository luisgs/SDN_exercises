# SDN_exercises
=============

### Several SDN exercises

This reposiroty stores two differents folders where five_layers represents my final university project. THe other folder contains only an example from Coursera training that my final prohject is based on.

### Five_layers
Requirements
  You need to have install a linux VM where Mininet is installed and capable to run correctly.
  
Files
  five_layers.py: this file contains the switch intelligence.
  mininetSlice.py this file describe the virtual topology, how many switches, hosts and the virtual way of their connections.
  
How to execute five_layer.
  First, run five_layers.py like
    pox.py log.level --DEBUG misc.five_layers misc.full_payload
  Note: if you have any problem, please, execute
    sudo mn -c
  
  Secondly, you need to run mininet with the topology decribed in mininetSlice.py like this: 
    sudo python pox/pox/misc/mininetSlice.py
  
  YOu will see how mininet is creating according to my topology all the netwroking devices. If you change the screen to five_layers tab, you will be able to see how my code starts to ask for information: STP, ARP...
  
  Once it is up, try some of the tests decribed in Objetives.txt file.
  
  Note: there is also another folder within five_layers directory amed Ostinato. This folder contains stream of data which will help you to generate different kind of traffic (TCP, IP only...)
  
  Hope that helps,
  Luis G.
