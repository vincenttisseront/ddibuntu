import * as auth from '../handlers/auth'
import * as ipam from '../handlers/ipam'
import * as dns from '../handlers/dns'
import * as dhcp from '../handlers/dhcp'
import * as filtering from '../handlers/filtering'
import * as importer from '../handlers/importer'
import * as system from '../handlers/system'
import * as snapshots from '../handlers/snapshots'
import * as adimport from '../handlers/adimport'
import * as netbox from '../handlers/netbox'
import * as discovery from '../handlers/discovery'
import * as cockpit from '../handlers/cockpit'
import * as cluster from '../handlers/cluster'
import * as adkrb from '../handlers/adkrb'
import * as search from '../handlers/search'
import * as hygiene from '../handlers/hygiene'
import * as tunnel from '../handlers/tunnel'
import * as backup from '../handlers/backup'
import * as alerts from '../handlers/alerts'
import { dispatch, routeCount } from '../utils/router'

// Chaque module enregistre ses routes à l'évaluation ; on vérifie ici qu'ils ont tous été inclus.
const modules = [auth, ipam, dns, dhcp, filtering, importer, system, snapshots, adimport, netbox, discovery, cockpit, cluster, adkrb, search, hygiene, tunnel, backup, alerts]
if (!modules.every((m) => m.registered) || routeCount() < 50) throw new Error(`[api] routes non enregistrées (${routeCount()})`)

export default defineEventHandler((event) => dispatch(event))
