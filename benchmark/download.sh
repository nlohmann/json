#!/bin/sh

git clone https://github.com/zeMirco/sf-city-lots-json.git
mv sf-city-lots-json/citylots.json .
rm -fr sf-city-lots-json

wget http://eu.battle.net/auction-data/258993a3c6b974ef3e6f22ea6f822720/auctions.json
