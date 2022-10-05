import { Hono } from 'hono'
import { basicAuth } from 'hono/basic-auth'

const api = new Hono()
const app = new Hono()

api.get('/message', (c) => {
  return c.json({
    message: 'Hello Pages!! This is Hono!!',
  })
})

app.route('/api', api)

const username = 'foo'
const password = 'bar'
app.use('/foo', basicAuth({ username, password }))

app.get('*', async (c) => {
  const res: Response = await c.env.ASSETS.fetch(c.req)
  return res
})

export default app
