export default Queue

function Queue(initial = []) {
  let xs = initial.slice()
  let index = 0

  return {
    get length() {
      return xs.length - index
    },
    remove: (x) => {
      const index = xs.indexOf(x)
      return index === -1
        ? null
        : (xs.splice(index, 1), x)
    },
    push: (x) => (xs.push(x), x),
    // Coffre: the newest, for the pool to take the connection idle the shortest, as pg-pool does: the others stay
    // idle, and close once idle_timeout passes, and the backends used stay few and warm.
    pop: () => {
      if (xs.length === index)
        return undefined
      const out = xs.pop()
      if (index === xs.length) {
        index = 0
        xs = []
      }
      return out
    },
    shift: () => {
      const out = xs[index++]

      if (index === xs.length) {
        index = 0
        xs = []
      } else {
        xs[index - 1] = undefined
      }

      return out
    }
  }
}
