// SPDX-License-Identifier: MIT

// File: @openzeppelin/contracts/security/ReentrancyGuard.sol


// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == _ENTERED;
    }
}

// File: @openzeppelin/contracts/utils/Context.sol


// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

pragma solidity ^0.8.0;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

// File: @openzeppelin/contracts/access/Ownable.sol


// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)

pragma solidity ^0.8.0;


/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// File: @openzeppelin/contracts/token/ERC20/IERC20.sol


// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// File: contracts/Harvester.sol


/**
 * @title Incentivizer Contract
 */
pragma solidity ^0.8.17;

contract Harvester is Ownable, ReentrancyGuard {
    IERC20 public GAMEToken;
    IERC20 public payToken;
    uint256 public totalRewards = 1;
    uint256 public eralength = 86400;
    uint256 public totalClaimedRewards;
    uint256 public immutable startTime;
    uint256 public rewardPerStamp;
    uint256 public numberOfParticipants = 0;
    uint256 public Duration = 604800;
    uint256 public timeLock = 7200;
    uint256 public TotalGAMESent = 1;
    uint256 public tax = 0;
    uint256 public TaxTotal = 0;
    uint256 public replenishTax = 0;
    uint256 public currentReplenish;
    uint256 public totalReplenish;
    uint256 public ERA = 0;
    uint256 public eraClock;
    uint256 public liveDays;
    uint256 private divisor = 100 ether;
    address private guard;  
    address public battledogs;
    bool public paused = false;   
    bool public replenisher = false; 

    mapping(address => uint256) public balances;
    mapping(address => Claim) public claimRewards;
    mapping(address => uint256) public entryMap;
    mapping(address => uint256) public UserClaims;
    mapping(address => bool) public blacklist;
    mapping(address => uint256) public Claimants;
    mapping(uint256 => uint256) public eraRewards;

    address[] public participants;

    struct Claim {
        uint256 eraAtBlock;
        uint256 GAMESent;
        uint256 rewardsOwed;
    }
    
    event RewardsUpdated(uint256 totalRewards);
    event RewardAddedByDev(uint256 amount);
    event RewardClaimedByUser(address indexed user, uint256 amount);
    event AddGAME(address indexed user, uint256 amount);
    event WithdrawGAME(address indexed user, uint256 amount);
    
    constructor(
        address _GAMEToken,
        address _payToken,
        address _battledogs,
        address _newGuard
    ) {
        GAMEToken = IERC20(_GAMEToken);
        payToken = IERC20(_payToken);
        battledogs = _battledogs;
        guard = _newGuard;
        startTime = block.timestamp;
        eraClock = startTime;
    }

    modifier onlyGuard() {
        require(msg.sender == guard, "Not authorized.");
        _;
    }

    modifier onlyAfterTimelock() {             
        require(entryMap[msg.sender] + timeLock < block.timestamp, "Timelocked.");
        _;
    }

    modifier onlyClaimant() {             
        require(UserClaims[msg.sender] + timeLock < block.timestamp, "Timelocked.");
        _;
    }

    function setEra() internal {
        uint256 timeElapsed = block.timestamp - startTime; // time elapsed in secs        
        uint256 totalDaysElapsed = timeElapsed / eralength; //  total Days since deploy

        uint256 daysElapsed = totalDaysElapsed - liveDays;// ensure uniform time across ERAs

        if (daysElapsed > 0) {
            liveDays += daysElapsed;
            for (uint256 i = 0; i < daysElapsed; i++) {
            // set rewards for each new ERA
                eraRewards[ERA] = rewardPerStamp; //ERA++ or ERA + 1
            //increment Era
            ERA++;
            }
        // Update the eraClock of current timestamp
        eraClock = block.timestamp;
        }   
    }

    function addGAME(uint256 _amount) public nonReentrant {
        require(!paused, "Contract is paused.");
        require(_amount > 0, "Amount must be greater than zero.");
        require(!blacklist[msg.sender], "Address is blacklisted.");
        require(GAMEToken.transferFrom(msg.sender, address(this), _amount), "Transfer failed.");
        setEra();
        Claim storage claimData = claimRewards[msg.sender];
        uint256 toll = (_amount * tax)/100;
        uint256 amount = _amount - toll;
        TaxTotal += toll;
        uint256 currentBalance = balances[msg.sender];
        uint256 newBalance = currentBalance + amount;
        balances[msg.sender] = newBalance;
        entryMap[msg.sender] = block.timestamp; // record the user's entry timestamp

        if (currentBalance == 0) {
            participants.push(msg.sender);
            numberOfParticipants += 1;
        }

        getClaim();
    
        // claimData.eraAtBlock = ERA;
        claimData.GAMESent += amount;
        TotalGAMESent += amount;
        setRewards();
        emit AddGAME(msg.sender, _amount);
    }

    /**
    * @dev Allows the user to withdraw their GAME tokens
    */
    function withdrawGAME() public nonReentrant onlyAfterTimelock {
        require(!paused, "Contract already paused.");
        require(balances[msg.sender] > 0, "No GAME tokens to withdraw.");        
        uint256 GAMEAmount = balances[msg.sender];
        require(GAMEToken.transfer(msg.sender, GAMEAmount), "Failed Transfer");    

        balances[msg.sender] = 0;
        TotalGAMESent -= GAMEAmount;
        Claim storage claimData = claimRewards[msg.sender];
        claimData.GAMESent = 0;

       setRewards();
       setEra();

        if (numberOfParticipants > 0) {
            numberOfParticipants -= 1;
            entryMap[msg.sender] = 0; // reset the user's entry timestamp
        }
        
        emit WithdrawGAME(msg.sender, GAMEAmount);
    }

    /**
    * @dev Adds new rewards to the contract
    * @param _amount The amount of rewards to add
    */
    function addRewards(uint256 _amount) external onlyOwner {
        payToken.transferFrom(msg.sender, address(this), _amount);
        setRewards();
        emit RewardAddedByDev(_amount);
    }

    function setRewards() internal {
        totalRewards = payToken.balanceOf(address(this));
        updateRewardPerStamp();        
        eraRewards[ERA] = rewardPerStamp;
        emit RewardsUpdated(totalRewards);
    }

    function resetRewards() external onlyOwner {
        setRewards();
    }

    function getClaim() internal {
            Claim storage claimData = claimRewards[msg.sender];// call the details for participant
            uint256 startPeriod = claimData.eraAtBlock;
            uint256 endPeriod = ERA;
            
            if (blacklist[msg.sender]) {
                claimData.rewardsOwed = 0;
            } else {
                //Find a way to calculate rewards for each ERA 
                uint256 rewardsAccrued;
                for (uint256 i = startPeriod; i < endPeriod; i++) {
                rewardsAccrued = (eraRewards[i] * claimData.GAMESent);
                claimData.rewardsOwed += rewardsAccrued;
                }             
            }
            claimData.eraAtBlock = ERA;
    }

    function updateRewardPerStamp() internal {
        rewardPerStamp = (totalRewards * divisor) / (TotalGAMESent * Duration);
    }

    function claim() public nonReentrant onlyClaimant {  
        require(!paused, "Contract already paused.");         
        require(!blacklist[msg.sender], "Address is blacklisted.");
        Claim storage claimData = claimRewards[msg.sender];
        if (claimData.eraAtBlock == ERA) {
        require(claimRewards[msg.sender].rewardsOwed > 0, "No rewards.");
        } else {            
        getClaim(); 
        }

        uint256 replenished = (claimData.rewardsOwed / 100) * replenishTax; 
        uint256 estimatedRewards = claimData.rewardsOwed - replenished;

        uint256 rewards =  estimatedRewards / divisor;
        uint256 replenish = replenished / divisor;
        
        require(payToken.transfer(msg.sender, rewards), "Transfer failed."); 
        require(payToken.transfer(battledogs, replenish), "Transfer failed.");       
        claimData.rewardsOwed = 0;
        // Update the total rewards claimed by the user
        Claimants[msg.sender] += rewards;
        totalClaimedRewards += rewards;
        currentReplenish += replenish;
        totalReplenish += replenish;
        setRewards();
        setEra();
        UserClaims[msg.sender] = block.timestamp; // record the user's claim timestamp       
        emit RewardClaimedByUser(msg.sender, rewards);
    }

    function withdraw(uint256 _binary, uint256 amount) external onlyOwner {
        require(amount > 0, "Amount must be greater than zero.");
        if (_binary > 1) {
            require(payToken.balanceOf(address(this)) >= amount, "Not Enough Reserves.");
            require(payToken.transfer(msg.sender, amount), "Transfer failed.");
        } else {
            require(amount <= TaxTotal, "Max Exceeded.");
            require(GAMEToken.balanceOf(address(this)) >= TaxTotal, "Not enough Reserves.");
            require(GAMEToken.transfer(msg.sender, amount), "Transfer failed.");
            TaxTotal -= amount;
        }
        setRewards();
    }

    function setDuration(uint256 _seconds) external onlyOwner {        
        getClaim();
        Duration = _seconds;
        updateRewardPerStamp();
    }

    function setTimeLock(uint256 _seconds) external onlyOwner {
        timeLock = _seconds;
    }

    function setEraLength(uint256 _seconds) external onlyOwner {
        eralength = _seconds;
    }

    function setTaxes (uint256 _stakeTax, uint256 _replenishTax ) external onlyOwner {
        tax = _stakeTax;
        replenishTax = _replenishTax;
    }

    function setGAMEToken(address _GAMEToken) external onlyOwner {
        GAMEToken = IERC20(_GAMEToken);
    }

    function setPayToken(address _payToken) external onlyOwner {
        payToken = IERC20(_payToken);
    }

    function setBattledogs (address _battledogs) external onlyOwner {
        battledogs = _battledogs;
    }

    function addToBlacklist(address[] calldata _addresses) external onlyOwner {
        for (uint256 i = 0; i < _addresses.length; i++) {
            blacklist[_addresses[i]] = true;
        }
    }

    function removeFromBlacklist(address[] calldata _addresses) external onlyOwner {
        for (uint256 i = 0; i < _addresses.length; i++) {
            blacklist[_addresses[i]] = false;
        }
    }

    event Pause();
    function pause() public onlyGuard {
        require(!paused, "Contract already paused.");
        paused = true;
        emit Pause();
    }

    event Unpause();
    function unpause() public onlyGuard {
        require(paused, "Contract not paused.");
        paused = false;
        emit Unpause();
    }

    function setGuard (address _newGuard) external onlyGuard {
        guard = _newGuard;
    }

    event ReplenishOn();
    function replenishOn(uint256 _replenishTax) external onlyOwner{
        require(!replenisher, "Replish already turned off.");
        replenisher = true;
        replenishTax = _replenishTax;
        emit ReplenishOn();
    }

    event ReplenishOff();
    function replenishOff() external onlyOwner {
        require(replenisher, "Replenish is in progress.");
        replenishTax = 0;
        currentReplenish = 0;
        replenisher = false;
        emit ReplenishOff();
    }
}              
