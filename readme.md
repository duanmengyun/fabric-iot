主要是两个源代码，链码再chaincode文件夹中，另一个是ticket.go

所有的模块都是在ubuntu中运行的,但提供了一个可以直接在windows下运行的该初始化程序ticket，不过因为后来源文件gopath什么的的一些问题就换到Ubuntu里运行调试了，它有一小部分和论文里描述的有些不同但大致一样，现在的ticket.go 重新build出来是一样的
初始化模块不需要介绍了，执行程序界面很清晰
ubuntu中./ticket即可，或者windows有可执行程序ticket.exe

区块链部分
智能合约以及整个系统的运行都是参考官方文档fabcar写的。
在vscode里标红没关系，在ubuntu中对应的链码文件执行如下语句,执行生成sum和mod文件还有vendor文件夹：
go mod init fabric-iot
go init tidy
go mod vendor

网络就是参考的那个simples里的test-network，直接createchannel然后部署自己写的链码就行，为了方便直接把链码放在了fabcar文件夹里然后删除原来的链码
1、启动网络前要先执行如下语句
export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=$PWD/../config/
并看一下peer version是否正确，出错的话网上搜一下教程，我记在csdn里了
2、启动通道
./network.sh up createChannel
3、部署链码
./network.sh deployCC -ccn fabric-iot -ccp ../chaincode/fabcar/go -ccv 1 -ccl go 
4、部署完链码之后执行以下语句
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

这是初始化后的一些数据，算是论文中使用的数据，可以自己再生成其他的，但要每次是会变的
1、先为主设备分发公钥对
最中心的master为用户颁发信任凭证，用户注册中心的公钥对
privateKey:
MHcCAQEEIJPYDzf0cGwKwWucM3NMs5FxztYwzh9rzpz2qMVc4fyooAoGCCqGSM49AwEHoUQDQgAEDFy3Xy3KJT+8VVSuA5lxckx+w5Ekx3Fd87sHBLGCaQOwIoi17VZN2Dwa6LKGHiTq4Ni9MQTR4TIqmfIMZW2cWQ==
 
 publicKey: NTU5MTU2OTY5ODU1NzQxNTAzMzI5ODE5NTIxNjUxNDUzMTE1OTA2Mjc2MTI3OTMyNzMxODUwNDMwODE1MTI2NDE0NzkyMjkwNTM0Nys3OTY2ODA3NzY5MzEwNTM3NjI1NjgzOTM5MzMyMDAxNTczNTU5OTY2MTcwODQ4MjgxMTg0MDQ1MTI5NTIzMTg3NDA4MTExMjMwMDYzMw==

域公钥对，主设备1，即domain1
master1的密钥对
私钥
MHcCAQEEIE1Mti1NsFk60CLRd6mUXlPw3n5kddCNIlNKygaq3eiaoAoGCCqGSM49AwEHoUQDQgAE4CZgiGUBAe5HBaZXI9zP967o58JwqKGOAUC9BNujJBfbBlEOTdYFGQJEgPaAGWOX4vJqGoTh/EtB+/CUP+eF3Q==
公钥
MTAxMzg1ODg0NTE1OTUyMjQ0MTY0MDUyNzAyNTEyNTM2NjY5MzMwMjAyNDM5NjQwOTEzMjIxODMwMzM3Mjk4MzEyMDU3MzI3OTIwMTUxKzk5MDY3Njc0MzQ5MjE0NDQxODc5NDgwMTgzOTk5OTM0NjMyOTU1MDM4NTk0MTQwMjU0Mjk5MDg3MzUwMDg3NjA2NDAwMDI5NTI1NDY5
2、信任凭证
device1的密钥对
privateKey:MHcCAQEEIJgK59eB3vKklI1V5ZeQ8EN0LBxA0JhyLpONothqXhoZoAoGCCqGSM49AwEHoUQDQgAERpFU21ohWGPM6kgibKen9RtWsMzQNovp0k3+yDq0tUHcS4bs2fCyDkdCRPrilyQJCxGMiR2qsO8ecu4KV1ELuA==
 publicKey:MzE5MTg2Nzc4ODU2MzQ3ODcxMjcwNDQwNDc0MzA5NTY1NzIyODUwOTcxNTgxMTk3MzU4NDQ1MDA4NjM5NjI4MTIzODU3MTg0ODIyNDErOTk2NDIyNzE0Mzc2ODY2NTEzNDAwNjMzMTY5MTE3NzczMTg2Njg5NjgwODg2NjEyNDQ1ODc5MDgyMTY5ODQ1MTM2MzMzNTE0MzcyNDA=

device1——domain1的ticket
38343437363835323630393931353136393635393731313037383030373437363833303737323533393834343133323337373634333836383635313633323137363635373834333536333336332b3632373539373131383332373136373035383530373739363032303331353136353031353335343330393238333236393732393638363632393935303039363638343533303835323735353134
device2——domain1ticket
39313732393137393735333937313634303438323232393130313230323336303238313938353838383035353234333537353434363032303631333832373730313834363933363635313932302b37393439303734313033363236333831333539393632353739343331313131363233313333343732333032303830393534373633333334323530353334313838303734393433363738363436
dmy的信任凭证
35383734373533333032373437333933383431353633323132373330353637373730393838323833383533353032323433323534303139363333353336333533373230383238353330383734332b3933323230363833313730303830363337323035303536323037373231333634313337363334313036303438383034363635363237373333393339393132363230373434363935393939363233
user1的ticket
31333938393037353934333835313730313631343634323034333834313331333234353733333531313632373439373036333139373832343634333130393236323336373733383437313935372b3836393134323930323836383234383835363131373238373334383937313238303330333837343136383137323233383835333330303930333730333334313836373733303232303032333830

区块链操作模块，使用的就是上面初始化模块的数据
1、创建域domain1
 peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n fabric-iot --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" -c '{"Args":["CreateDomain","domain1","master1","MTAxMzg1ODg0NTE1OTUyMjQ0MTY0MDUyNzAyNTEyNTM2NjY5MzMwMjAyNDM5NjQwOTEzMjIxODMwMzM3Mjk4MzEyMDU3MzI3OTIwMTUxKzk5MDY3Njc0MzQ5MjE0NDQxODc5NDgwMTgzOTk5OTM0NjMyOTU1MDM4NTk0MTQwMjU0Mjk5MDg3MzUwMDg3NjA2NDAwMDI5NTI1NDY5"]}'

2、创建设备device1
 peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n fabric-iot --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" -c '{"Args":["CreateDevice","device1","domain1","38343437363835323630393931353136393635393731313037383030373437363833303737323533393834343133323337373634333836383635313633323137363635373834333536333336332b3632373539373131383332373136373035383530373739363032303331353136353031353335343330393238333236393732393638363632393935303039363638343533303835323735353134"]}'

3、身份认证
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n fabric-iot --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" -c '{"Args":["authentication","device1","domain1"]}'
4、添加policy
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n fabric-iot --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" -c '{"Args":["addpolicy","device1","domain1","pdevice1video","manager","XJTU","device1video","MHcCAQEEIJgK59eB3vKklI1V5ZeQ8EN0LBxA0JhyLpONothqXhoZoAoGCCqGSM49AwEHoUQDQgAERpFU21ohWGPM6kgibKen9RtWsMzQNovp0k3+yDq0tUHcS4bs2fCyDkdCRPrilyQJCxGMiR2qsO8ecu4KV1ELuA==","aeskey","00:00","12:00","1"]}'

5、添加url 
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n fabric-iot --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" -c '{"Args":["addinfo","device1video","BLbBG3sqjBwz0j9PInNV859JXgISaL5CVAeKKN1bnM8L7RocvXoWHiKAETApk4fnFso/QG7yTds3HiN24ra/Kq3h7b7BMAcOoVfnGQCkUVQRM1SiCy61FeFeOJRuX7YwAuC9+SjqlB92I6aJFLvads72ZLR8F7VQ5hesCHrgzGge+ejOuAbSrXutW48y"]}'

6、添加用户dmy和user1
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n fabric-iot --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" -c '{"Args":["CreateUser","dmy","1214784622","manager","XJTU","31343636373138363630333030373538313830393830373832393832343738373535333833353737363833393237393436393833383331393637373031393439353930363836353233323737332b3631313239383735393634313137383633313038363539393039353538373236343836303830313232313330303834393132323634333436393535343436323335303535353238333435383335"]}'

peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n fabric-iot --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" -c '{"Args":["CreateUser","user1","123456","student","XJTU","31333938393037353934333835313730313631343634323034333834313331333234353733333531313632373439373036333139373832343634333130393236323336373733383437313935372b3836393134323930323836383234383835363131373238373334383937313238303330333837343136383137323233383835333330303930333730333334313836373733303232303032333830"]}'

7、用户访问控制
peer chaincode query -C mychannel -n fabric-iot -c '{"Args":["accesscontrol","dmy","1214784622","device1video"]}'
peer chaincode query -C mychannel -n fabric-iot -c '{"Args":["accesscontrol","user1","123456","device1video"]}'


