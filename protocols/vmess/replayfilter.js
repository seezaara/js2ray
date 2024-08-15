"use strict";
function InsertUnique(cf, data) {
    if (cf.has(data)) {
        return false
    }
    cf.add(data)
    return true
}
function NewReplayFilter(interval) {
    return {
        poolA: new Set(),
        poolB: new Set(),
        poolSwap: false,
        lastSwap: Math.round(new Date() / 1000),
        interval: interval
    }
}
// Check determines if there are duplicate records.
function Check(filter, sum) {
    var now = Math.round(new Date() / 1000) 
    if (now - filter.lastSwap >= filter.interval) {  
        if (filter.poolSwap) {
            filter.poolA.clear()
        } else {
            filter.poolB.clear()
        }
        filter.poolSwap = !filter.poolSwap
        filter.lastSwap = now
    }
    return InsertUnique(filter.poolA, sum) && InsertUnique(filter.poolB, sum)
}
module.exports = {
    NewReplayFilter,
    Check
}