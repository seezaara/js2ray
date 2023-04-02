

const CuckooFilter = require('cuckoo-filter').CuckooFilter
const replayFilterCapacity = 100000 

function InsertUnique(cf, data) {
    if (cf.contains(data)) {
        return false
    }
    return cf.add(data)
}
function NewReplayFilter(interval) {
    return {
        poolA: [],
        poolB: [],
        poolSwap: false,
        lastSwap: 0,
        interval: interval
    }
}
// Check determines if there are duplicate records.
function Check(filter, sum) {
    var now = Math.round(new Date() / 1000)
    if (filter.lastSwap == 0) {
        filter.lastSwap = now
        filter.poolA = new CuckooFilter(replayFilterCapacity, 2, 4)
        filter.poolB = new CuckooFilter(replayFilterCapacity, 2, 4)
    }

    if (now - filter.lastSwap >= filter.Interval) {
        if (filter.poolSwap) {
            filter.poolA = new CuckooFilter(replayFilterCapacity, 2, 4)
        } else {
            filter.poolB = new CuckooFilter(replayFilterCapacity, 2, 4)
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