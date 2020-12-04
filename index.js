const PDClient = require('node-pagerduty')
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager')

const client = new SecretManagerServiceClient()
const ORGID = '<ORGID>'
const PD_API_TOKEN = ''
const PD_INTEGRATION_KEY = ''
const SCC_URL = `https://console.cloud.google.com/security/command-center/findings?authuser=0&organizationId=${ORGID}&orgonly=true&supportedpurview=organizationId&view_type=vt_finding_type&vt_finding_type=All&columns=category,sourceProperties.ProjectId,securityMarks.marks`

/**
 * Background Cloud Function to be triggered by Pub/Sub.
 * This function is exported by index.js, and executed when
 * the trigger topic receives a message.
 *
 * @param {object} message The Pub/Sub message.
 * @param {object} context The event metadata and it won't be used
 */
exports.createPdEvent = async (message, context) => {
  console.info('New message received.')
  console.info('Getting Pagerduty credentials.')

  const pd = new PDClient(PD_API_TOKEN)

  console.info('Parsing message')

  if (!message.data) {
    throw new Error('Bad request payload')
  }

  const data = JSON.parse(Buffer.from(message.data, 'base64'))

  if (!data.finding) {
    throw new Error('Bad request payload. Missing attribute "finding"')
  }

  console.info('Creating PagerDuty incident')

  const payload = createEventPayload({
    category: data.finding.category,
    name: data.finding.name,
    sourceProperties: cleanSensitiveInformation(data.finding.sourceProperties),
    integrationKey: PD_INTEGRATION_KEY
  })

  pd.events.sendEvent(payload)
    .then(res => console.log(res))
    .catch(err => {
      console.error(err)
      throw new Error(err)
    })
}

const createEventPayload = ({ category, name, sourceProperties, integrationKey }) => {
  const findingDetailsUrl = `${SCC_URL}&resourceId=${decodeURIComponent(name)}`
  return {
    payload: {
      summary: `GCP Security Finding - ${category}`,
      timestamp: (new Date()).toISOString(),
      severity: 'warning',
      source: findingDetailsUrl,
      component: 'gcloud',
      custom_details: sourceProperties
    },
    routing_key: integrationKey,
    dedup_key: name,
    event_action: 'trigger',
    client: 'GCP Security Command Center',
    client_url: SCC_URL,
    links: [
      {
        href: findingDetailsUrl,
        text: 'Finding Details'
      }
    ]
  }
}

/**
 * remove sensitive information from finding.sourceProperties
  * @param {object} data
  */
const cleanSensitiveInformation = (data) => {
  const removeFields = ['Environment_Variables']
  removeFields.forEach(field => {
    data[field] = '<redacted>'
  })

  return data
}
