<template>
  <div class="analysis-detail" v-loading="loading">
    <!-- Header -->
    <div class="page-header" v-if="analysis">
      <div class="header-left">
        <el-button :icon="ArrowLeft" text @click="$router.back()">Back</el-button>
        <div class="title-block">
          <h2>{{ analysis.filename }}</h2>
          <div class="meta">
            <el-tag :type="statusType" size="small">{{ analysis.status }}</el-tag>
            <span class="meta-item" v-if="data?.file_info?.total_packets">
              {{ formatNum(data.file_info.total_packets) }} packets
            </span>
            <span class="meta-item" v-if="data?.file_info?.duration_sec">
              {{ formatDuration(data.file_info.duration_sec) }}
            </span>
            <span class="meta-item">{{ analysis.created_at?.substring(0, 16).replace('T', ' ') }}</span>
          </div>
        </div>
      </div>
      <div class="issue-badges" v-if="data?.issue_counts">
        <el-tag type="danger" effect="dark" v-if="data.issue_counts.critical > 0">
          {{ data.issue_counts.critical }} Critical
        </el-tag>
        <el-tag type="warning" effect="dark" v-if="data.issue_counts.warning > 0">
          {{ data.issue_counts.warning }} Warning
        </el-tag>
        <el-tag type="success" v-if="data.issue_counts.total === 0">No Issues</el-tag>
      </div>
    </div>

    <template v-if="data">
      <el-tabs v-model="activeTab" type="border-card" class="main-tabs">

        <!-- ── Tab 1: Overview ───────────────────────────────────────────── -->
        <el-tab-pane label="Overview" name="overview">
          <div class="two-col">
            <el-card class="summary-card" shadow="never">
              <template #header><span class="card-title">Executive Summary</span></template>
              <p class="summary-text">{{ data.executive_summary }}</p>
            </el-card>
            <el-card shadow="never">
              <template #header><span class="card-title">Capture Info</span></template>
              <el-descriptions :column="1" border size="small">
                <el-descriptions-item label="Total Packets">{{ formatNum(data.file_info?.total_packets) }}</el-descriptions-item>
                <el-descriptions-item label="Duration">{{ formatDuration(data.file_info?.duration_sec) }}</el-descriptions-item>
                <el-descriptions-item label="File Size">{{ formatBytes(data.file_info?.file_size_bytes) }}</el-descriptions-item>
                <el-descriptions-item label="First Packet">{{ data.file_info?.first_packet || '—' }}</el-descriptions-item>
                <el-descriptions-item label="Last Packet">{{ data.file_info?.last_packet || '—' }}</el-descriptions-item>
                <el-descriptions-item label="Packets Analyzed">{{ formatNum(data.packets_analyzed) }}</el-descriptions-item>
                <el-descriptions-item label="Analysis Time">{{ data.analysis_time_sec }}s</el-descriptions-item>
              </el-descriptions>
            </el-card>
          </div>

          <el-card shadow="never" class="mt-4">
            <template #header><span class="card-title">Protocol Distribution</span></template>
            <div class="proto-grid">
              <div v-for="(count, proto) in data.protocol_hierarchy" :key="proto" class="proto-chip">
                <span class="proto-name">{{ proto }}</span>
                <el-tag size="small">{{ formatNum(count) }}</el-tag>
              </div>
            </div>
          </el-card>

          <el-card shadow="never" class="mt-4">
            <template #header><span class="card-title">Technical Summary</span></template>
            <div class="technical-summary" v-html="renderMarkdown(data.technical_summary)"></div>
          </el-card>
        </el-tab-pane>

        <!-- ── Tab 2: Hosts ──────────────────────────────────────────────── -->
        <el-tab-pane label="Hosts" name="hosts">
          <el-card shadow="never">
            <template #header><span class="card-title">Host Profiles (sorted by anomaly score)</span></template>
            <el-table :data="data.hosts || data.ip_endpoints" size="small" stripe>
              <el-table-column prop="ip" label="IP" width="140" />
              <el-table-column prop="role" label="Role" width="110">
                <template #default="{ row }">
                  <el-tag size="small" type="info">{{ row.role || '—' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="Anomaly" width="110" sortable prop="anomaly_score">
                <template #default="{ row }">
                  <span v-if="row.anomaly_score != null" :style="`color:${row.anomaly_score >= 5 ? '#f56c6c' : row.anomaly_score >= 2 ? '#e6a23c' : '#67c23a'}`">
                    {{ row.anomaly_score?.toFixed(1) }}
                  </span>
                  <span v-else>—</span>
                </template>
              </el-table-column>
              <el-table-column label="Sent" sortable prop="bytes_sent">
                <template #default="{ row }">{{ formatBytes(row.bytes_sent || row.tx_bytes) }}</template>
              </el-table-column>
              <el-table-column label="Received">
                <template #default="{ row }">{{ formatBytes(row.bytes_recv || row.rx_bytes) }}</template>
              </el-table-column>
              <el-table-column prop="unique_peers" label="Peers" width="80" />
              <el-table-column prop="unique_dst_ports" label="Ports" width="80" />
              <el-table-column label="Behaviors" show-overflow-tooltip>
                <template #default="{ row }">
                  <span class="text-warn" v-if="row.suspicious_behaviors?.length">
                    {{ row.suspicious_behaviors.join('; ') }}
                  </span>
                  <span v-else-if="row.periodic_interval_sec > 0" class="text-danger">
                    Beaconing every {{ row.periodic_interval_sec }}s
                  </span>
                  <span v-else style="color:#909399">—</span>
                </template>
              </el-table-column>
            </el-table>
          </el-card>

          <!-- Host stories -->
          <el-card shadow="never" class="mt-4" v-if="Object.keys(data.host_stories || {}).length">
            <template #header><span class="card-title">Host Narratives</span></template>
            <div class="host-stories">
              <div v-for="(story, ip) in data.host_stories" :key="ip" class="host-story">
                <span class="story-ip">{{ ip }}</span>
                <p>{{ story }}</p>
              </div>
            </div>
          </el-card>
        </el-tab-pane>

        <!-- ── Tab 3: Conversations ──────────────────────────────────────── -->
        <el-tab-pane label="Conversations" name="conversations">
          <el-card shadow="never">
            <template #header><span class="card-title">Top TCP Conversations</span></template>
            <el-table :data="data.tcp_conversations" size="small" stripe>
              <el-table-column label="Source" min-width="150">
                <template #default="{ row }">{{ row.src_ip }}:{{ row.src_port }}</template>
              </el-table-column>
              <el-table-column label="Destination" min-width="150">
                <template #default="{ row }">{{ row.dst_ip }}:{{ row.dst_port }}</template>
              </el-table-column>
              <el-table-column label="Bytes" sortable>
                <template #default="{ row }">{{ formatBytes(row.bytes) }}</template>
              </el-table-column>
              <el-table-column prop="packets" label="Packets" sortable>
                <template #default="{ row }">{{ formatNum(row.packets) }}</template>
              </el-table-column>
              <el-table-column label="Duration">
                <template #default="{ row }">{{ row.duration?.toFixed(3) }}s</template>
              </el-table-column>
            </el-table>
          </el-card>

          <!-- Flow interpretations for top flows -->
          <el-card shadow="never" class="mt-4" v-if="Object.keys(data.flow_stories || {}).length">
            <template #header><span class="card-title">Flow Interpretations (top flows by volume)</span></template>
            <div class="flow-stories">
              <el-collapse accordion>
                <el-collapse-item
                  v-for="(story, flowKey) in data.flow_stories"
                  :key="flowKey"
                  :name="flowKey"
                >
                  <template #title>
                    <span class="flow-key-label">{{ flowKey }}</span>
                  </template>
                  <div class="flow-story-body">
                    <div v-for="(block, bi) in story.split('\n\n')" :key="bi" class="interp-block">
                      <span v-html="renderMarkdown(block)"></span>
                    </div>
                  </div>
                </el-collapse-item>
              </el-collapse>
            </div>
          </el-card>
        </el-tab-pane>

        <!-- ── Tab 4: Protocols ──────────────────────────────────────────── -->
        <el-tab-pane label="Protocols" name="protocols">
          <div class="two-col">
            <el-card shadow="never" v-if="data.protocols?.icmp?.type_counts">
              <template #header><span class="card-title">ICMP</span></template>
              <kv-table :data="data.protocols.icmp.type_counts" />
            </el-card>
            <el-card shadow="never" v-if="data.protocols?.arp">
              <template #header><span class="card-title">ARP</span></template>
              <el-descriptions :column="1" border size="small">
                <el-descriptions-item label="Requests">{{ data.protocols.arp.requests }}</el-descriptions-item>
                <el-descriptions-item label="Replies">{{ data.protocols.arp.replies }}</el-descriptions-item>
                <el-descriptions-item label="Gratuitous ARPs">{{ data.protocols.arp.gratuitous_count }}</el-descriptions-item>
              </el-descriptions>
            </el-card>
            <el-card shadow="never" v-if="data.protocols?.dhcp">
              <template #header><span class="card-title">DHCP</span></template>
              <kv-table :data="data.protocols.dhcp.type_counts" />
            </el-card>
            <el-card shadow="never" v-if="data.protocols?.smtp?.command_counts">
              <template #header><span class="card-title">SMTP</span></template>
              <kv-table :data="data.protocols.smtp.command_counts" />
            </el-card>
            <el-card shadow="never" v-if="data.protocols?.ftp?.command_counts">
              <template #header><span class="card-title">FTP</span></template>
              <kv-table :data="data.protocols.ftp.command_counts" />
            </el-card>
            <el-card shadow="never" v-if="data.protocols?.ssh?.version_counts">
              <template #header><span class="card-title">SSH Versions</span></template>
              <kv-table :data="data.protocols.ssh.version_counts" />
            </el-card>
            <el-card shadow="never" v-if="data.protocols?.smb">
              <template #header><span class="card-title">SMB2 Commands</span></template>
              <kv-table :data="data.protocols.smb.smb2_commands" />
            </el-card>
            <el-card shadow="never" v-if="data.protocols?.kerberos?.message_counts">
              <template #header><span class="card-title">Kerberos</span></template>
              <kv-table :data="data.protocols.kerberos.message_counts" />
            </el-card>
            <el-card shadow="never" v-if="data.protocols?.snmp">
              <template #header><span class="card-title">SNMP Versions</span></template>
              <kv-table :data="data.protocols.snmp.version_counts" />
            </el-card>
            <el-card shadow="never" v-if="data.protocols?.quic?.total > 0">
              <template #header><span class="card-title">QUIC</span></template>
              <el-descriptions :column="1" border size="small">
                <el-descriptions-item label="Total Frames">{{ data.protocols.quic.total }}</el-descriptions-item>
              </el-descriptions>
            </el-card>
          </div>
        </el-tab-pane>

        <!-- ── Tab 5: DNS ────────────────────────────────────────────────── -->
        <el-tab-pane label="DNS" name="dns">
          <div class="stats-row">
            <stat-card label="Total Queries" :value="formatNum(data.dns?.total_queries)" />
            <stat-card label="Unique Domains" :value="formatNum(data.dns?.unique_domains)" />
            <stat-card label="NXDOMAIN" :value="formatNum(data.dns?.nxdomain_count)" type="danger" />
            <stat-card label="SERVFAIL" :value="formatNum(data.dns?.servfail_count)" type="warning" />
            <stat-card label="Avg RTT" :value="(data.dns?.avg_rtt_ms || 0) + 'ms'" />
            <stat-card label="Unanswered" :value="formatNum(data.dns?.unanswered_count)" />
          </div>
          <div class="two-col mt-4">
            <el-card shadow="never">
              <template #header><span class="card-title">Top Queried Domains</span></template>
              <el-table :data="data.dns?.top_queries" size="small" stripe>
                <el-table-column prop="domain" label="Domain" />
                <el-table-column prop="count" label="Count" width="100" sortable />
              </el-table>
            </el-card>
            <el-card shadow="never" v-if="data.dns?.nxdomains?.length">
              <template #header><span class="card-title">NXDOMAIN Domains</span></template>
              <el-table :data="data.dns.nxdomains" size="small" stripe>
                <el-table-column prop="domain" label="Domain" />
                <el-table-column prop="count" label="Count" width="100" sortable />
              </el-table>
            </el-card>
            <el-card shadow="never">
              <template #header><span class="card-title">Query Types</span></template>
              <kv-table :data="data.dns?.query_types" />
            </el-card>
            <el-card shadow="never">
              <template #header><span class="card-title">Top DNS Resolvers</span></template>
              <el-table :data="data.dns?.resolvers" size="small" stripe>
                <el-table-column prop="ip" label="Resolver IP" />
                <el-table-column prop="count" label="Queries" width="100" />
              </el-table>
            </el-card>
          </div>
        </el-tab-pane>

        <!-- ── Tab 6: Web (HTTP) ─────────────────────────────────────────── -->
        <el-tab-pane label="Web" name="web">
          <div class="stats-row">
            <stat-card label="Requests" :value="formatNum(data.http?.total_requests)" />
            <stat-card label="4xx Errors" :value="formatNum(data.http?.error_4xx)" type="warning" />
            <stat-card label="5xx Errors" :value="formatNum(data.http?.error_5xx)" type="danger" />
            <stat-card label="Avg RTT" :value="(data.http?.avg_rtt_ms || 0) + 'ms'" />
          </div>
          <div class="two-col mt-4">
            <el-card shadow="never">
              <template #header><span class="card-title">HTTP Methods</span></template>
              <kv-table :data="data.http?.method_counts" />
            </el-card>
            <el-card shadow="never">
              <template #header><span class="card-title">Status Codes</span></template>
              <kv-table :data="data.http?.status_counts" />
            </el-card>
            <el-card shadow="never">
              <template #header><span class="card-title">Top Hosts</span></template>
              <el-table :data="data.http?.top_hosts" size="small" stripe>
                <el-table-column prop="host" label="Host" />
                <el-table-column prop="count" label="Requests" width="100" />
              </el-table>
            </el-card>
            <el-card shadow="never">
              <template #header><span class="card-title">Top URIs</span></template>
              <el-table :data="data.http?.top_uris" size="small" stripe>
                <el-table-column prop="uri" label="URI" show-overflow-tooltip />
                <el-table-column prop="count" label="Count" width="80" />
              </el-table>
            </el-card>
            <el-card shadow="never" v-if="data.http?.top_user_agents?.length">
              <template #header><span class="card-title">User Agents</span></template>
              <el-table :data="data.http.top_user_agents" size="small" stripe>
                <el-table-column prop="ua" label="User Agent" show-overflow-tooltip />
                <el-table-column prop="count" label="Count" width="80" />
              </el-table>
            </el-card>
          </div>
        </el-tab-pane>

        <!-- ── Tab 7: TLS ────────────────────────────────────────────────── -->
        <el-tab-pane label="TLS" name="tls">
          <div class="stats-row">
            <stat-card label="TLS Streams" :value="formatNum(data.tls?.total_tls_streams)" />
            <stat-card label="Unique SNI" :value="formatNum(data.tls?.unique_sni)" />
            <stat-card label="Deprecated Ver." :value="formatNum(data.tls?.deprecated_version_count)" type="danger" />
            <stat-card label="Weak Ciphers" :value="formatNum(data.tls?.weak_cipher_count)" type="warning" />
          </div>
          <div class="two-col mt-4">
            <el-card shadow="never">
              <template #header><span class="card-title">TLS Versions</span></template>
              <kv-table :data="data.tls?.version_counts" />
            </el-card>
            <el-card shadow="never">
              <template #header><span class="card-title">Handshake Types</span></template>
              <kv-table :data="data.tls?.handshake_counts" />
            </el-card>
            <el-card shadow="never">
              <template #header><span class="card-title">Top SNI Hosts</span></template>
              <el-table :data="data.tls?.top_sni" size="small" stripe>
                <el-table-column prop="sni" label="SNI / Hostname" />
                <el-table-column prop="count" label="Connections" width="110" sortable />
              </el-table>
            </el-card>
          </div>
        </el-tab-pane>

        <!-- ── Tab 8: TCP Issues ─────────────────────────────────────────── -->
        <el-tab-pane label="TCP Issues" name="tcp">
          <div class="stats-row">
            <stat-card label="Sessions" :value="formatNum(data.tcp?.total_sessions)" />
            <stat-card label="Retransmissions" :value="formatNum(data.tcp?.retransmissions)" type="warning" />
            <stat-card label="RST Packets" :value="formatNum(data.tcp?.resets)" type="danger" />
            <stat-card label="Failed Handshakes" :value="formatNum(data.tcp?.failed_handshakes)" type="danger" />
            <stat-card label="Dup ACKs" :value="formatNum(data.tcp?.duplicate_acks)" type="warning" />
            <stat-card label="Zero Windows" :value="formatNum(data.tcp?.zero_windows)" type="warning" />
          </div>
          <el-card shadow="never" class="mt-4">
            <template #header><span class="card-title">TCP Sessions (sorted by bytes — expand row for interpretation)</span></template>
            <el-table :data="data.tcp?.sessions" size="small" stripe row-key="stream_id">
              <el-table-column type="expand">
                <template #default="{ row }">
                  <div class="session-interpretation" v-if="row.interpretation">
                    <div v-for="(block, bi) in row.interpretation.split('\n\n')" :key="bi" class="interp-block">
                      <span v-html="renderMarkdown(block)"></span>
                    </div>
                  </div>
                  <div class="session-interpretation" v-else style="color:#909399;font-style:italic">
                    No interpretation available for this session.
                  </div>
                </template>
              </el-table-column>
              <el-table-column prop="stream_id" label="Stream" width="75" />
              <el-table-column label="Source" min-width="145">
                <template #default="{ row }">{{ row.src_ip }}:{{ row.src_port }}</template>
              </el-table-column>
              <el-table-column label="Destination" min-width="145">
                <template #default="{ row }">{{ row.dst_ip }}:{{ row.dst_port }}</template>
              </el-table-column>
              <el-table-column prop="state" label="State" width="115">
                <template #default="{ row }">
                  <el-tag :type="stateType(row.state)" size="small">{{ row.state }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="Bytes" sortable>
                <template #default="{ row }">{{ formatBytes((row.bytes_sent || 0) + (row.bytes_recv || 0)) }}</template>
              </el-table-column>
              <el-table-column label="Pkts" width="75" sortable>
                <template #default="{ row }">{{ (row.packets_sent || 0) + (row.packets_recv || 0) }}</template>
              </el-table-column>
              <el-table-column prop="retransmissions" label="Retrans" width="80" sortable>
                <template #default="{ row }">
                  <span :class="{ 'text-danger': row.retransmissions > 5 }">{{ row.retransmissions }}</span>
                </template>
              </el-table-column>
              <el-table-column label="Duration" width="85">
                <template #default="{ row }">{{ row.duration_sec }}s</template>
              </el-table-column>
            </el-table>
          </el-card>
        </el-tab-pane>

        <!-- ── Tab 9: Security Findings ──────────────────────────────────── -->
        <el-tab-pane label="Security" name="security">
          <div v-if="!data.all_issues?.length" class="empty-state">
            <el-icon size="48" color="#67c23a"><CircleCheck /></el-icon>
            <p>No security issues detected</p>
          </div>
          <div v-else class="findings-list">
            <el-card
              v-for="(issue, idx) in data.all_issues"
              :key="idx"
              shadow="never"
              class="finding-card"
              :class="`finding-${issue.severity}`"
            >
              <div class="finding-header">
                <el-tag :type="issueTagType(issue.severity)" effect="dark" size="small">
                  {{ issue.severity?.toUpperCase() }}
                </el-tag>
                <el-tag type="info" size="small" style="margin-left:6px">{{ issue.category }}</el-tag>
                <span class="finding-title">{{ issue.title }}</span>
                <span class="finding-count" v-if="issue.count">× {{ formatNum(issue.count) }}</span>
              </div>

              <!-- Brief description -->
              <p class="finding-desc">{{ issue.description }}</p>

              <!-- Score + confidence -->
              <div class="finding-meta" v-if="issue.score != null">
                <el-tag size="small" type="danger" plain>Score {{ issue.score?.toFixed(1) }}</el-tag>
                <el-tag size="small" plain>Confidence: {{ issue.confidence }}</el-tag>
              </div>

              <!-- Full explanation (what is happening + why it matters) -->
              <div class="finding-explanation" v-if="issue.explanation">
                <div class="interp-label">What is happening</div>
                <p>{{ issue.explanation }}</p>
              </div>

              <!-- Root cause / possible causes -->
              <div class="finding-causes" v-if="issue.possible_causes?.length">
                <div class="interp-label">Likely root causes</div>
                <ul class="causes-list">
                  <li v-for="(c, ci) in issue.possible_causes" :key="ci">{{ c }}</li>
                </ul>
              </div>

              <!-- MITRE ATT&CK badges -->
              <div class="mitre-badges" v-if="issue.mitre?.length">
                <a
                  v-for="m in issue.mitre.slice(0, 3)"
                  :key="m.technique_id"
                  :href="m.url"
                  target="_blank"
                  class="mitre-badge"
                >
                  {{ m.technique_id }}: {{ m.technique_name }}
                </a>
              </div>

              <!-- Evidence samples -->
              <div class="finding-evidence" v-if="issue.evidence?.samples?.length">
                <div class="interp-label">Evidence</div>
                <code v-for="(s, si) in issue.evidence.samples.slice(0, 5)" :key="si">{{ s }}</code>
              </div>

              <!-- Recommended actions -->
              <div class="finding-actions" v-if="issue.recommended_actions?.length">
                <div class="actions-label">Recommended Actions</div>
                <ul>
                  <li v-for="(act, ai) in issue.recommended_actions" :key="ai">{{ act }}</li>
                </ul>
              </div>
            </el-card>
          </div>
        </el-tab-pane>

        <!-- ── Tab 10: Timeline ──────────────────────────────────────────── -->
        <el-tab-pane label="Timeline" name="timeline">
          <div class="timeline-filters">
            <el-select v-model="timelineFilter" placeholder="Filter events" clearable size="small" style="width:200px">
              <el-option label="All Events" value="" />
              <el-option label="DNS" value="dns" />
              <el-option label="HTTP" value="http" />
              <el-option label="TLS" value="tls" />
              <el-option label="DHCP" value="dhcp" />
              <el-option label="RDP" value="rdp" />
              <el-option label="Security" value="scan,spoof,beacon,movement" />
            </el-select>
            <el-select v-model="timelineSeverity" placeholder="Severity" clearable size="small" style="width:150px;margin-left:8px">
              <el-option label="All" value="" />
              <el-option label="Critical" value="critical" />
              <el-option label="Warning" value="warning" />
              <el-option label="Info" value="info" />
            </el-select>
            <span class="event-count">{{ filteredTimeline.length }} events</span>
          </div>

          <el-timeline class="event-timeline">
            <el-timeline-item
              v-for="(event, idx) in filteredTimeline.slice(0, 200)"
              :key="idx"
              :type="timelineItemType(event.severity)"
              :timestamp="formatTs(event.ts)"
              placement="top"
            >
              <div class="timeline-event">
                <strong>{{ event.label }}</strong>
                <p class="event-detail">{{ event.detail }}</p>
              </div>
            </el-timeline-item>
          </el-timeline>
          <div v-if="filteredTimeline.length > 200" class="truncation-note">
            Showing first 200 of {{ filteredTimeline.length }} events
          </div>
          <el-empty v-if="filteredTimeline.length === 0" description="No timeline events" />
        </el-tab-pane>

        <!-- ── Tab 11: Expert Info ───────────────────────────────────────── -->
        <el-tab-pane label="Expert Info" name="expert">
          <el-card shadow="never">
            <template #header><span class="card-title">tshark Expert Analysis</span></template>
            <el-table :data="data.expert_info" size="small" stripe v-if="data.expert_info?.length">
              <el-table-column prop="severity" label="Severity" width="100">
                <template #default="{ row }">
                  <el-tag :type="expertTagType(row.severity)" size="small">{{ row.severity }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="count" label="Count" width="80" sortable />
              <el-table-column prop="message" label="Message" />
            </el-table>
            <el-empty v-else description="No expert info available" />
          </el-card>
        </el-tab-pane>

      </el-tabs>
    </template>

    <el-empty v-else-if="!loading" description="Analysis data not available" />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ArrowLeft, CircleCheck, Sunny } from '@element-plus/icons-vue'
import api from '@/api'

const route = useRoute()
const loading = ref(true)
const analysis = ref(null)
const data = ref(null)
const activeTab = ref('overview')
const timelineFilter = ref('')
const timelineSeverity = ref('')

onMounted(async () => {
  try {
    const res = await api.get(`/analyses/${route.params.id}`)
    analysis.value = res.data
    data.value = res.data.data
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
})

const statusType = computed(() => {
  const s = analysis.value?.status
  if (s === 'completed') return 'success'
  if (s === 'failed') return 'danger'
  if (s === 'processing') return 'warning'
  return 'info'
})

const filteredTimeline = computed(() => {
  let events = data.value?.timeline || []
  if (timelineFilter.value) {
    const filters = timelineFilter.value.split(',')
    events = events.filter(e => filters.some(f => e.type?.includes(f)))
  }
  if (timelineSeverity.value) {
    events = events.filter(e => e.severity === timelineSeverity.value)
  }
  return events
})

function formatNum(n) {
  if (n == null) return '0'
  return Number(n).toLocaleString()
}

function formatBytes(b) {
  if (!b) return '0 B'
  b = Number(b)
  if (b < 1024) return b + ' B'
  if (b < 1024 ** 2) return (b / 1024).toFixed(1) + ' KB'
  if (b < 1024 ** 3) return (b / 1024 ** 2).toFixed(1) + ' MB'
  return (b / 1024 ** 3).toFixed(2) + ' GB'
}

function formatDuration(s) {
  if (!s) return '0s'
  s = Number(s)
  if (s < 60) return s.toFixed(1) + 's'
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

function formatTs(ts) {
  if (!ts || ts === 0) return '—'
  return new Date(ts * 1000).toISOString().replace('T', ' ').substring(0, 19)
}

function renderMarkdown(text) {
  if (!text) return ''
  return text
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\n\n/g, '<br><br>')
}

function stateType(state) {
  if (state === 'fin-closed') return 'success'
  if (state === 'reset') return 'danger'
  if (state === 'half-open') return 'warning'
  if (state === 'established') return 'primary'
  return 'info'
}

function issueTagType(sev) {
  if (sev === 'critical') return 'danger'
  if (sev === 'warning') return 'warning'
  return 'info'
}

function timelineItemType(sev) {
  if (sev === 'critical') return 'danger'
  if (sev === 'warning') return 'warning'
  if (sev === 'info') return 'primary'
  return 'info'
}

function expertTagType(sev) {
  if (sev === 'error') return 'danger'
  if (sev === 'warn') return 'warning'
  if (sev === 'note') return 'info'
  return ''
}
</script>

<!-- Inline sub-components -->
<script>
import { h, defineComponent } from 'vue'
import { ElTable, ElTableColumn } from 'element-plus'

const KvTable = defineComponent({
  name: 'KvTable',
  props: { data: Object },
  setup(props) {
    return () => {
      if (!props.data || !Object.keys(props.data || {}).length) {
        return h('p', { style: 'color:#909399;font-size:13px' }, 'No data')
      }
      const rows = Object.entries(props.data).sort((a, b) => Number(b[1]) - Number(a[1]))
      return h(ElTable, { data: rows, size: 'small', stripe: true }, {
        default: () => [
          h(ElTableColumn, { label: 'Key', formatter: (row) => row[0] }),
          h(ElTableColumn, { label: 'Count', width: 100, formatter: (row) => Number(row[1]).toLocaleString() }),
        ]
      })
    }
  }
})

const StatCard = defineComponent({
  name: 'StatCard',
  props: { label: String, value: [String, Number], type: String },
  setup(props) {
    const colors = { danger: '#f56c6c', warning: '#e6a23c', success: '#67c23a' }
    return () => h('div', {
      style: `background:#fff;border:1px solid #ebeef5;border-radius:6px;padding:14px 20px;text-align:center;min-width:100px;`
    }, [
      h('div', { style: `font-size:22px;font-weight:700;color:${colors[props.type] || '#303133'}` }, props.value),
      h('div', { style: 'font-size:12px;color:#909399;margin-top:4px' }, props.label),
    ])
  }
})

export default { components: { KvTable, StatCard } }
</script>

<style scoped>
.analysis-detail { padding: 20px; }

.page-header {
  display: flex; justify-content: space-between; align-items: flex-start;
  margin-bottom: 16px; flex-wrap: wrap; gap: 12px;
}
.header-left { display: flex; align-items: flex-start; gap: 12px; }
.title-block h2 { margin: 0 0 6px; font-size: 18px; }
.meta { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.meta-item { font-size: 13px; color: #606266; }
.issue-badges { display: flex; gap: 8px; align-items: center; }

.main-tabs :deep(.el-tabs__content) { padding: 16px; }

.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }

.stats-row { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
.mt-4 { margin-top: 16px; }

.summary-text { font-size: 14px; line-height: 1.8; color: #303133; }
.technical-summary { font-size: 13px; line-height: 1.8; }
.card-title { font-weight: 600; font-size: 14px; }

.proto-grid { display: flex; flex-wrap: wrap; gap: 8px; }
.proto-chip {
  display: flex; align-items: center; gap: 6px;
  background: #f5f7fa; border-radius: 4px; padding: 4px 10px;
}
.proto-name { font-size: 13px; font-weight: 500; }

.findings-list { display: flex; flex-direction: column; gap: 12px; }
.finding-card { border-left: 4px solid #dcdfe6; }
.finding-critical { border-left-color: #f56c6c; }
.finding-warning { border-left-color: #e6a23c; }
.finding-info { border-left-color: #409eff; }
.finding-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
.finding-title { font-weight: 600; font-size: 14px; flex: 1; }
.finding-count { color: #909399; font-size: 12px; }
.finding-desc { font-size: 13px; color: #606266; margin: 0 0 8px; line-height: 1.6; }
.finding-rec {
  display: flex; align-items: flex-start; gap: 6px;
  background: #f0f9eb; border-radius: 4px; padding: 8px 10px;
  font-size: 12px; color: #529b2e;
}
.finding-examples { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px; }
.finding-examples code {
  background: #f5f7fa; padding: 2px 6px; border-radius: 3px;
  font-size: 12px; color: #606266;
}

.timeline-filters { display: flex; align-items: center; margin-bottom: 16px; }
.event-count { margin-left: 12px; font-size: 12px; color: #909399; }
.event-timeline { padding: 8px 0; }
.timeline-event strong { font-size: 13px; }
.event-detail { font-size: 12px; color: #909399; margin: 2px 0 0; }
.truncation-note { text-align: center; color: #909399; font-size: 12px; margin-top: 8px; }

.empty-state { text-align: center; padding: 60px 20px; }
.text-danger { color: #f56c6c; }
.text-warn { color: #e6a23c; }

.finding-meta { display: flex; gap: 6px; margin: 4px 0 8px; }
.mitre-badges { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
.mitre-badge {
  display: inline-flex; align-items: center; padding: 2px 8px;
  background: #ecf5ff; border-radius: 3px; font-size: 11px;
  color: #409eff; text-decoration: none; border: 1px solid #c6e2ff;
  transition: background 0.2s;
}
.mitre-badge:hover { background: #c6e2ff; }
.finding-evidence { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.finding-evidence code {
  background: #f5f7fa; padding: 2px 6px; border-radius: 3px;
  font-size: 11px; color: #606266; font-family: monospace;
}
.finding-actions { margin-top: 8px; font-size: 12px; }
.actions-label { font-weight: 600; margin-bottom: 4px; color: #606266; }
.finding-actions ul { margin: 0; padding-left: 18px; color: #606266; }
.finding-actions li { margin: 2px 0; }

.host-stories { display: flex; flex-direction: column; gap: 12px; }
.host-story { background: #f5f7fa; border-radius: 4px; padding: 10px 14px; }
.story-ip { font-weight: 700; font-size: 13px; color: #409eff; }
.host-story p { margin: 4px 0 0; font-size: 13px; color: #606266; line-height: 1.6; }

/* ── Interpretation / analysis blocks ── */
.interp-label {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #909399;
  margin: 10px 0 4px;
}
.finding-explanation {
  background: #f0f9ff;
  border-left: 3px solid #409eff;
  padding: 8px 12px;
  border-radius: 0 4px 4px 0;
  margin: 8px 0;
  font-size: 13px;
  color: #303133;
  line-height: 1.7;
}
.finding-explanation p { margin: 0; }
.finding-causes {
  background: #fdf6ec;
  border-left: 3px solid #e6a23c;
  padding: 8px 12px;
  border-radius: 0 4px 4px 0;
  margin: 8px 0;
}
.causes-list { margin: 0; padding-left: 18px; font-size: 13px; color: #606266; line-height: 1.7; }
.causes-list li { margin: 2px 0; }

/* ── Session interpretation (expand row) ── */
.session-interpretation {
  padding: 12px 16px;
  background: #fafafa;
  font-size: 13px;
  color: #303133;
  line-height: 1.7;
}
.interp-block {
  margin-bottom: 8px;
}
.interp-block strong { color: #303133; }
.interp-block p { margin: 2px 0; }

/* ── Flow stories (conversations tab) ── */
.flow-stories { font-size: 13px; }
.flow-key-label {
  font-family: monospace;
  font-size: 12px;
  color: #409eff;
}
.flow-story-body {
  padding: 8px 4px;
  color: #303133;
  line-height: 1.7;
}
</style>
