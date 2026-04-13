<template>
  <div class="monitoring">
    <div class="page-header">
      <div>
        <h2>Path Monitoring</h2>
        <p>
          Re-runs your saved path queries on a schedule and alerts you when
          a previously healthy path drifts.
        </p>
      </div>
      <div class="header-actions">
        <el-button @click="fetchAll" :loading="loading">Refresh</el-button>
        <el-button type="primary" @click="openCreate">
          <el-icon><Plus /></el-icon>
          New Monitor
        </el-button>
      </div>
    </div>

    <!-- System intelligence panel -->
    <div
      v-if="insights && monitors.length"
      class="insights-panel"
    >
      <div class="insights-header" @click="insightsExpanded = !insightsExpanded">
        <span class="insights-title">
          <el-icon><DataAnalysis /></el-icon>
          System Intelligence
        </span>
        <span class="insights-mini">
          {{ insights.monitor_count }} monitors ·
          avg risk {{ insights.avg_risk_score }}/100 ·
          {{ insights.action_required_count }} need action
        </span>
        <el-icon class="expand-icon" :class="{ rotated: insightsExpanded }">
          <ArrowDown />
        </el-icon>
      </div>

      <div v-show="insightsExpanded" class="insights-body">
        <!-- Headline bullets -->
        <div v-if="insights.headlines?.length" class="insight-section">
          <ul class="insight-bullets">
            <li v-for="(h, i) in insights.headlines" :key="i">{{ h }}</li>
          </ul>
        </div>

        <div class="insight-cards">
          <!-- Risk distribution -->
          <div class="insight-card">
            <div class="insight-card-title">Risk Distribution</div>
            <div class="risk-bars">
              <div
                v-for="lvl in ['critical', 'high', 'medium', 'low']"
                :key="lvl"
                class="risk-bar-row"
              >
                <span class="bar-label" :class="`bar-${lvl}`">{{ lvl }}</span>
                <div class="bar-track">
                  <div
                    class="bar-fill"
                    :class="`bar-${lvl}`"
                    :style="{ width: barWidth(insights.risk_distribution[lvl]) }"
                  ></div>
                </div>
                <span class="bar-count">{{ insights.risk_distribution[lvl] || 0 }}</span>
              </div>
            </div>
          </div>

          <!-- Top root cause -->
          <div class="insight-card">
            <div class="insight-card-title">Root Cause Analysis</div>
            <div v-if="insights.dominant_root_cause" class="rc-dominant">
              <span class="rc-label">{{ insights.dominant_root_cause }}</span>
              is the most common root cause
            </div>
            <div v-else class="rc-empty">No outcomes recorded yet</div>
            <div
              v-if="Object.keys(insights.root_cause_distribution || {}).length"
              class="rc-dist"
            >
              <span
                v-for="(count, type) in insights.root_cause_distribution"
                :key="type"
                class="rc-chip"
              >{{ type }} ({{ count }})</span>
            </div>
          </div>

          <!-- Signal reliability -->
          <div class="insight-card">
            <div class="insight-card-title">Signal Reliability</div>
            <div v-if="insights.reliable_signals?.length">
              <div
                v-for="s in insights.reliable_signals.slice(0, 3)"
                :key="s.signal"
                class="signal-row"
              >
                <span class="signal-name">{{ s.signal.replace(/_/g, ' ') }}</span>
                <el-tag type="success" size="small" effect="plain">
                  {{ s.confirmed }}/{{ s.total }} confirmed
                </el-tag>
              </div>
            </div>
            <div v-if="insights.noisy_signals?.length" class="noisy-section">
              <span class="noisy-label">Noisy:</span>
              <span
                v-for="s in insights.noisy_signals.slice(0, 2)"
                :key="s.signal"
                class="signal-noisy"
              >{{ s.signal.replace(/_/g, ' ') }} ({{ Math.round(s.fp_rate * 100) }}% FP)</span>
            </div>
            <div
              v-if="!insights.reliable_signals?.length && !insights.noisy_signals?.length"
              class="rc-empty"
            >Not enough outcome data</div>
          </div>
        </div>

        <!-- Systemic issues -->
        <div
          v-if="insights.systemic_destinations?.length"
          class="systemic-block"
        >
          <div class="insight-card-title">
            <el-icon><WarningFilled /></el-icon>
            Potential Systemic Issues
          </div>
          <div
            v-for="sd in insights.systemic_destinations"
            :key="sd.destination_ip"
            class="systemic-row"
          >
            <code>{{ sd.destination_ip }}</code>
            — {{ sd.affected_count }} monitors affected:
            <span
              v-for="m in sd.monitors"
              :key="m.id"
              class="systemic-monitor"
            >
              {{ m.name }}
              <el-tag
                :type="riskTagType(m.risk_level)"
                size="small"
                effect="plain"
              >{{ m.risk_level }}</el-tag>
            </span>
          </div>
        </div>

        <!-- Shared impairments -->
        <div
          v-if="insights.shared_impairments?.length"
          class="shared-block"
        >
          <div class="insight-card-title">Cross-Monitor Impairments</div>
          <el-tag
            v-for="si in insights.shared_impairments"
            :key="si.impairment"
            type="warning"
            effect="plain"
            class="shared-tag"
          >{{ si.display }} · {{ si.monitor_count }} monitors</el-tag>
        </div>
      </div>
    </div>

    <div v-if="error" class="empty-state error">{{ error }}</div>

    <div v-else-if="loading && !monitors.length" class="empty-state">
      <el-icon class="spinning"><Loading /></el-icon>
      <span>Loading monitors…</span>
    </div>

    <div v-else-if="!monitors.length" class="empty-state">
      <p>No monitored paths yet.</p>
      <p class="hint">
        Save a path-analysis query first, then create a monitor here to watch
        for drift.
      </p>
    </div>

    <!-- "What should I look at first?" banner — only shown when there is at
         least one path with non-trivial risk. -->
    <div
      v-if="topRiskMonitor && topRiskMonitor.risk_score >= 25"
      class="top-risk-banner"
      :class="`risk-${topRiskMonitor.risk_level}`"
    >
      <el-icon><WarningFilled /></el-icon>
      <div class="banner-body">
        <div class="banner-title">
          Highest risk: <strong>{{ topRiskMonitor.saved_query_name }}</strong>
          <span class="banner-score">{{ topRiskMonitor.risk_score }}/100</span>
          <el-tag
            :type="riskTagType(topRiskMonitor.risk_level)"
            size="small"
            effect="dark"
          >{{ topRiskMonitor.risk_level.toUpperCase() }}</el-tag>
        </div>
        <div class="banner-sub">
          {{ topRiskMonitor.source_ip }} → {{ topRiskMonitor.destination_ip }}
          <template v-if="topRiskMonitor.recommended_action">
            · {{ topRiskMonitor.recommended_action }}
          </template>
        </div>
      </div>
    </div>

    <div v-if="monitors.length" class="list-toolbar">
      <span class="ranking-hint">
        Ranked by operational risk — highest first.
      </span>
      <el-radio-group
        v-model="filterMode"
        size="small"
      >
        <el-radio-button label="all">
          All <span class="filter-count">{{ monitors.length }}</span>
        </el-radio-button>
        <el-radio-button label="action_required">
          Action required <span class="filter-count">{{ actionRequiredCount }}</span>
        </el-radio-button>
      </el-radio-group>
    </div>

    <div v-if="monitors.length && !filteredMonitors.length" class="empty-state">
      <p>Nothing needs attention right now.</p>
      <p class="hint">Switch to <strong>All</strong> to see every monitored path.</p>
    </div>

    <div v-if="filteredMonitors.length" class="monitor-list">
      <div
        v-for="m in filteredMonitors"
        :key="m.id"
        class="monitor-card"
        :class="[
          severityClass(m.last_drift_severity),
          `risk-${m.risk_level || 'low'}`,
          m.action_required ? 'is-actionable' : '',
        ]"
      >
        <!-- Risk strip across the top of every card -->
        <div class="risk-strip" :class="`risk-${m.risk_level || 'low'}`">
          <div class="risk-label">
            <el-icon v-if="m.risk_level === 'critical'"><WarningFilled /></el-icon>
            <strong>RISK {{ m.risk_score ?? 0 }}/100</strong>
            <el-tag
              :type="riskTagType(m.risk_level)"
              size="small"
              effect="dark"
            >{{ (m.risk_level || 'low').toUpperCase() }}</el-tag>
            <el-tag
              v-if="m.action_required"
              type="danger"
              size="small"
              effect="dark"
              class="action-badge"
            >
              <el-icon><Bell /></el-icon>
              ACTION REQUIRED
            </el-tag>
            <el-tag
              v-if="m.suppressed"
              size="small"
              effect="plain"
              class="suppressed-badge"
            >MUTED</el-tag>
            <el-tag
              v-if="m.baseline_applied"
              type="info"
              size="small"
              effect="plain"
            >BASELINE ADAPTED</el-tag>
          </div>
          <div
            v-if="m.risk_drivers && m.risk_drivers.length"
            class="risk-drivers"
          >
            {{ m.risk_drivers.slice(0, 2).join(' · ') }}
          </div>
        </div>

        <!-- Recommended action block — only when there's something to do -->
        <div
          v-if="m.action_required && m.recommended_action"
          class="action-block"
          :class="`priority-${m.priority}`"
        >
          <div class="action-headline">
            <span class="priority-pill" :class="`priority-${m.priority}`">
              {{ priorityLabel(m.priority) }}
            </span>
            <strong>{{ m.recommended_action }}</strong>
          </div>
          <ul
            v-if="m.action_focus && m.action_focus.length > 1"
            class="action-focus"
          >
            <li v-for="(f, i) in m.action_focus.slice(1)" :key="i">{{ f }}</li>
          </ul>
        </div>
        <div class="card-head">
          <div class="card-head-left">
            <h3>{{ m.saved_query_name || `Query #${m.saved_query_id}` }}</h3>
            <div class="path-line">
              <code>{{ m.source_ip }}</code>
              <span class="arrow">→</span>
              <code>
                {{ m.destination_ip
                }}<template v-if="m.destination_port">:{{ m.destination_port }}</template>
              </code>
            </div>
            <div class="sub-line">
              on <strong>{{ m.analysis_filename || m.analysis_id }}</strong>
              · every {{ m.schedule_interval_minutes }} min
            </div>
          </div>
          <div class="card-head-right">
            <el-tag
              v-if="!m.enabled"
              type="info"
              effect="plain"
              size="small"
            >Paused</el-tag>
            <el-tag
              v-else-if="m.last_drift_severity && m.last_drift_severity !== 'none'"
              :type="severityTagType(m.last_drift_severity)"
              effect="dark"
              size="small"
            >{{ m.last_drift_severity.toUpperCase() }}</el-tag>
            <el-tag
              v-else-if="m.has_baseline"
              type="success"
              effect="plain"
              size="small"
            >Healthy</el-tag>
            <el-tag
              v-else
              type="info"
              effect="plain"
              size="small"
            >No baseline yet</el-tag>
          </div>
        </div>

        <div class="card-meta">
          <div>
            <span class="meta-label">Last run</span>
            <span class="meta-value">{{ formatTime(m.last_run_at) || '—' }}</span>
          </div>
          <div>
            <span class="meta-label">Last change</span>
            <span class="meta-value">{{ formatTime(m.last_change_at) || '—' }}</span>
          </div>
          <div v-if="m.last_outcome">
            <span class="meta-label">Last resolution</span>
            <span class="meta-value outcome-tag" :class="`oc-${m.last_outcome}`">
              {{ outcomeLabel(m.last_outcome) }}
            </span>
          </div>
          <div v-if="m.outcome_count">
            <span class="meta-label">Outcomes</span>
            <span class="meta-value">{{ m.outcome_count }}</span>
          </div>
        </div>

        <!-- Historical hints from outcome learning -->
        <div
          v-if="m.outcome_hints && m.outcome_hints.length"
          class="outcome-hints"
        >
          <div class="trend-section-title">Historical insights</div>
          <ul>
            <li v-for="(h, i) in m.outcome_hints" :key="i">{{ h }}</li>
          </ul>
        </div>

        <div
          v-if="m.last_change_summary && m.last_change_summary.changes?.length"
          class="change-block"
        >
          <div class="change-title">
            What changed
            <span
              v-if="m.last_change_summary.severity"
              class="severity-pill"
              :class="severityClass(m.last_change_summary.severity)"
            >{{ m.last_change_summary.severity.toUpperCase() }}</span>
          </div>
          <ul>
            <li
              v-for="(c, i) in m.last_change_summary.changes"
              :key="i"
            >{{ c }}</li>
          </ul>
          <div
            v-if="actionRequired(m.last_change_summary.severity)"
            class="action-required"
          >
            <el-icon><Warning /></el-icon>
            Review needed — analysis was moved to
            <strong>needs review</strong>.
          </div>
        </div>

        <div class="card-actions">
          <el-button size="small" @click="runNow(m)" :loading="runningId === m.id">
            <el-icon><VideoPlay /></el-icon>
            Run Now
          </el-button>
          <el-button size="small" @click="toggleEnabled(m)">
            {{ m.enabled ? 'Pause' : 'Resume' }}
          </el-button>
          <el-button
            size="small"
            @click="toggleTrend(m)"
            :loading="trendLoadingId === m.id"
          >
            {{ expandedId === m.id ? 'Hide trend' : 'Show trend' }}
            <span class="run-count" v-if="m.run_count"> · {{ m.run_count }} runs</span>
          </el-button>
          <el-button
            size="small"
            type="warning"
            plain
            @click="openOutcomeDialog(m)"
          >Mark outcome</el-button>
          <el-dropdown
            size="small"
            trigger="click"
            @command="(cmd) => handleNoiseControl(cmd, m)"
          >
            <el-button size="small" plain>
              Noise control <el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="mute">
                  Mute all alerts
                </el-dropdown-item>
                <el-dropdown-item command="snooze">
                  Snooze 24h
                </el-dropdown-item>
                <el-dropdown-item command="baseline">
                  Edit baseline expectations
                </el-dropdown-item>
                <el-dropdown-item
                  v-if="m.suppressed"
                  command="unsuppress"
                  divided
                >
                  Remove all suppressions
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <el-button
            size="small"
            type="danger"
            plain
            @click="deleteMonitor(m)"
          >Delete</el-button>
          <el-button
            size="small"
            link
            @click="$router.push(`/analysis/${m.analysis_id}`)"
          >Open analysis →</el-button>
        </div>

        <!-- Expandable trend panel -->
        <div v-if="expandedId === m.id" class="trend-panel">
          <div v-if="!trendData[m.id]" class="trend-loading">Loading…</div>
          <template v-else-if="trendData[m.id].total_runs === 0">
            <p class="trend-empty">No runs yet. Press Run Now to capture a baseline.</p>
          </template>
          <template v-else>
            <!-- Headline metrics -->
            <div class="trend-metrics">
              <div class="metric">
                <div class="metric-label">Health</div>
                <div
                  class="metric-value"
                  :class="healthClass(trendData[m.id].health_score)"
                >{{ trendData[m.id].health_score }}<small>/100</small></div>
              </div>
              <div class="metric">
                <div class="metric-label">Total runs</div>
                <div class="metric-value">{{ trendData[m.id].total_runs }}</div>
              </div>
              <div class="metric">
                <div class="metric-label">Action-required</div>
                <div class="metric-value">{{ trendData[m.id].action_required_runs }}</div>
              </div>
              <div class="metric">
                <div class="metric-label">Episodes</div>
                <div class="metric-value">{{ trendData[m.id].regression_episodes }}</div>
              </div>
            </div>

            <!-- Worsening callout -->
            <div
              v-if="trendData[m.id].worsening"
              class="worsening-callout"
            >
              <el-icon><WarningFilled /></el-icon>
              <div>
                <strong>This path is getting worse.</strong>
                <ul>
                  <li v-for="(r, i) in trendData[m.id].worsening_reasons" :key="i">{{ r }}</li>
                </ul>
              </div>
            </div>

            <!-- Recurring impairment badges -->
            <div
              v-if="trendData[m.id].recurring_impairments.length"
              class="recurring-block"
            >
              <div class="trend-section-title">Recurring impairments</div>
              <el-tag
                v-for="imp in trendData[m.id].recurring_impairments"
                :key="imp.token"
                type="warning"
                effect="plain"
                class="recurring-tag"
              >
                {{ imp.token.replace(/_/g, ' ') }} · ×{{ imp.count }}
              </el-tag>
            </div>

            <!-- Trend lines: confidence + backend delay -->
            <div class="trend-lines">
              <div class="trend-line">
                <div class="trend-section-title">
                  Confidence
                  <span class="slope" :class="slopeClass(trendData[m.id].confidence_trend.slope, true)">
                    {{ slopeLabel(trendData[m.id].confidence_trend.slope) }}
                  </span>
                </div>
                <div class="trend-numbers">
                  prev avg: {{ trendData[m.id].confidence_trend.prev_avg ?? '—' }}
                  → recent avg: {{ trendData[m.id].confidence_trend.recent_avg ?? '—' }}
                </div>
                <Sparkline
                  v-if="trendHistory[m.id]"
                  :values="trendHistory[m.id].map(r => r.path_confidence_score)"
                  :colour="'#409eff'"
                />
              </div>
              <div
                v-if="trendData[m.id].backend_delay_trend.key"
                class="trend-line"
              >
                <div class="trend-section-title">
                  {{ trendData[m.id].backend_delay_trend.key.replace(/_/g, ' ') }}
                  <span class="slope" :class="slopeClass(trendData[m.id].backend_delay_trend.slope, false)">
                    {{ slopeLabel(trendData[m.id].backend_delay_trend.slope) }}
                  </span>
                </div>
                <div class="trend-numbers">
                  prev avg: {{ trendData[m.id].backend_delay_trend.prev_avg ?? '—' }}
                  → recent avg: {{ trendData[m.id].backend_delay_trend.recent_avg ?? '—' }} ms
                </div>
                <Sparkline
                  v-if="trendHistory[m.id]"
                  :values="trendHistory[m.id].map(r => (r.timing || {})[trendData[m.id].backend_delay_trend.key])"
                  :colour="'#e6a23c'"
                />
              </div>
            </div>

            <!-- Drift timeline (compact) -->
            <div class="drift-timeline">
              <div class="trend-section-title">Drift timeline</div>
              <div class="timeline-row">
                <span
                  v-for="(r, i) in (trendHistory[m.id] || [])"
                  :key="i"
                  class="timeline-cell"
                  :class="`sev-${r.drift_severity}`"
                  :title="`${formatTime(r.run_at)} — ${r.drift_severity} (${r.connection_outcome})`"
                ></span>
              </div>
              <div class="timeline-legend">
                <span class="legend"><span class="dot sev-none"></span>none</span>
                <span class="legend"><span class="dot sev-info"></span>info</span>
                <span class="legend"><span class="dot sev-warning"></span>warning</span>
                <span class="legend"><span class="dot sev-critical"></span>critical</span>
              </div>
            </div>

            <!-- Recent runs table (compact) -->
            <div class="recent-runs">
              <div class="trend-section-title">Recent runs</div>
              <table>
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Outcome</th>
                    <th>Drift</th>
                    <th>Confidence</th>
                    <th>Primary impairment</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="r in (trendHistory[m.id] || []).slice(0, 8)" :key="r.id">
                    <td>{{ formatTime(r.run_at) }}</td>
                    <td>{{ r.connection_outcome }}</td>
                    <td>
                      <span class="severity-pill" :class="severityClass(r.drift_severity)">
                        {{ r.drift_severity }}
                      </span>
                    </td>
                    <td>{{ r.path_confidence_score }}%</td>
                    <td>{{ r.primary_impairment || '—' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>
        </div>
      </div>
    </div>

    <!-- Create dialog -->
    <el-dialog
      v-model="createOpen"
      title="New monitored path"
      width="520px"
    >
      <el-form :model="createForm" label-position="top">
        <el-form-item label="Saved query">
          <el-select
            v-model="createForm.saved_query_id"
            placeholder="Pick a saved path query"
            style="width: 100%"
          >
            <el-option
              v-for="q in savedQueries"
              :key="q.id"
              :label="`${q.name} (${q.source_ip} → ${q.destination_ip})`"
              :value="q.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="Target analysis (PCAP to re-run against)">
          <el-select
            v-model="createForm.analysis_id"
            placeholder="Pick a completed analysis"
            filterable
            style="width: 100%"
          >
            <el-option
              v-for="a in analyses"
              :key="a.id"
              :label="`${a.filename} — ${a.id.slice(0, 8)}`"
              :value="a.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="Poll interval (minutes)">
          <el-input-number
            v-model="createForm.schedule_interval_minutes"
            :min="1"
            :max="10080"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createOpen = false">Cancel</el-button>
        <el-button
          type="primary"
          :disabled="!canCreate"
          :loading="creating"
          @click="submitCreate"
        >Create</el-button>
      </template>
    </el-dialog>

    <!-- Baseline expectations dialog -->
    <el-dialog
      v-model="baselineOpen"
      title="Baseline expectations"
      width="500px"
    >
      <p class="baseline-hint">
        Set accepted ranges and known noisy signals so the system
        does not flag them as action-required.
      </p>
      <el-form :model="baselineForm" label-position="top">
        <el-form-item label="Max accepted backend delay (ms)">
          <el-input-number
            v-model="baselineForm.accepted_delay_max_ms"
            :min="0"
            :step="10"
            placeholder="None"
          />
        </el-form-item>
        <el-form-item label="Min accepted confidence (%)">
          <el-input-number
            v-model="baselineForm.accepted_confidence_min"
            :min="0"
            :max="100"
            placeholder="None"
          />
        </el-form-item>
        <el-form-item label="Known noisy impairments (comma-separated tokens)">
          <el-input
            v-model="baselineForm.known_noisy_raw"
            placeholder="e.g. packet_loss, return_path_problem"
          />
        </el-form-item>
        <el-form-item label="Known visibility gaps">
          <el-input
            v-model="baselineForm.known_gaps_raw"
            type="textarea"
            :rows="2"
            placeholder="e.g. no span port on switch B"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="baselineOpen = false">Cancel</el-button>
        <el-button type="danger" plain @click="clearBaseline">Clear</el-button>
        <el-button type="primary" :loading="baselineSaving" @click="saveBaseline">Save</el-button>
      </template>
    </el-dialog>

    <!-- Mark outcome dialog -->
    <el-dialog
      v-model="outcomeOpen"
      title="Mark investigation outcome"
      width="480px"
    >
      <el-form :model="outcomeForm" label-position="top">
        <el-form-item label="What was the result?">
          <el-radio-group v-model="outcomeForm.outcome">
            <el-radio label="issue_confirmed">Issue confirmed</el-radio>
            <el-radio label="false_positive">False positive</el-radio>
            <el-radio label="transient_issue">Transient / self-resolved</el-radio>
            <el-radio label="root_cause_identified">Root cause identified</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item
          v-if="outcomeForm.outcome === 'root_cause_identified'"
          label="Root cause type"
        >
          <el-select v-model="outcomeForm.root_cause_type" style="width: 100%">
            <el-option label="Network" value="network" />
            <el-option label="Firewall" value="firewall" />
            <el-option label="Application" value="app" />
            <el-option label="DNS" value="dns" />
            <el-option label="Unknown" value="unknown" />
          </el-select>
        </el-form-item>
        <el-form-item label="Note (optional)">
          <el-input
            v-model="outcomeForm.note"
            type="textarea"
            :rows="2"
            placeholder="What did you find?"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="outcomeOpen = false">Cancel</el-button>
        <el-button
          type="primary"
          :disabled="!outcomeForm.outcome"
          :loading="outcomeSaving"
          @click="submitOutcome"
        >Save outcome</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, h, onMounted, ref } from 'vue'
import {
  ArrowDown, Bell, DataAnalysis, Loading, Plus, VideoPlay, Warning,
  WarningFilled,
} from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'

// Tiny inline SVG sparkline so we don't pull in a charting dep for one feature.
const Sparkline = {
  props: {
    values: { type: Array, required: true },
    colour: { type: String, default: '#409eff' },
  },
  setup(props) {
    return () => {
      const nums = (props.values || []).filter(v => typeof v === 'number')
      if (nums.length < 2) {
        return h('div', { class: 'sparkline-empty' }, 'not enough data')
      }
      const w = 240
      const hgt = 36
      const min = Math.min(...nums)
      const max = Math.max(...nums)
      const range = max - min || 1
      const step = w / (nums.length - 1)
      const points = nums.map((v, i) => {
        const x = (i * step).toFixed(1)
        const y = (hgt - ((v - min) / range) * hgt).toFixed(1)
        return `${x},${y}`
      }).join(' ')
      return h('svg', { width: w, height: hgt, class: 'sparkline' }, [
        h('polyline', {
          fill: 'none',
          stroke: props.colour,
          'stroke-width': 2,
          points,
        }),
      ])
    }
  },
}

const monitors = ref([])
const savedQueries = ref([])
const analyses = ref([])
const loading = ref(false)
const error = ref(null)
const runningId = ref(null)

// System insights
const insights = ref(null)
const insightsExpanded = ref(true)

// Trend panel state — keyed by monitor id so multiple panels can stay open.
const expandedId = ref(null)
const trendLoadingId = ref(null)
const trendData = ref({})      // { [monitorId]: trendDigest }
const trendHistory = ref({})   // { [monitorId]: runDict[] (newest first) }

const createOpen = ref(false)
const creating = ref(false)
const createForm = ref({
  saved_query_id: null,
  analysis_id: null,
  schedule_interval_minutes: 60,
})
const canCreate = computed(
  () => !!createForm.value.saved_query_id && !!createForm.value.analysis_id,
)

// Highest-risk monitor (the list is already sorted by risk desc server-side,
// so this is just monitors[0]). Used by the "what should I look at first?"
// banner above the list.
const topRiskMonitor = computed(() => monitors.value[0] || null)

// "Action required" filter — when set, hide passive/healthy monitors so
// the analyst sees a focused triage queue.
const filterMode = ref('all')   // 'all' | 'action_required'
const actionRequiredCount = computed(
  () => monitors.value.filter(m => m.action_required).length,
)
const filteredMonitors = computed(() => {
  if (filterMode.value === 'action_required') {
    return monitors.value.filter(m => m.action_required)
  }
  return monitors.value
})

function riskTagType(level) {
  if (level === 'critical') return 'danger'
  if (level === 'high')     return 'warning'
  if (level === 'medium')   return 'info'
  return 'success'
}

function priorityLabel(priority) {
  if (priority === 'critical') return 'IMMEDIATE'
  if (priority === 'high')     return 'NEEDS ATTENTION'
  if (priority === 'medium')   return 'WATCH'
  return 'OK'
}

async function fetchAll() {
  loading.value = true
  error.value = null
  try {
    const [m, q, a, ins] = await Promise.all([
      api.get('/path-monitors'),
      api.get('/path-analysis/saved-queries'),
      api.get('/analyses'),
      api.get('/system-insights'),
    ])
    monitors.value = m.data
    savedQueries.value = q.data
    analyses.value = (a.data || []).filter(x => x.status === 'completed')
    insights.value = ins.data
  } catch (e) {
    error.value = e?.response?.data?.detail || e?.message || 'Failed to load'
  } finally {
    loading.value = false
  }
}

function openCreate() {
  createForm.value = {
    saved_query_id: savedQueries.value[0]?.id || null,
    analysis_id: analyses.value[0]?.id || null,
    schedule_interval_minutes: 60,
  }
  createOpen.value = true
}

async function submitCreate() {
  creating.value = true
  try {
    await api.post('/path-monitors', createForm.value)
    createOpen.value = false
    ElMessage.success('Monitor created')
    await fetchAll()
  } catch (e) {
    ElMessage.error(
      e?.response?.data?.detail || e?.message || 'Failed to create monitor',
    )
  } finally {
    creating.value = false
  }
}

async function runNow(m) {
  runningId.value = m.id
  try {
    const res = await api.post(`/path-monitors/${m.id}/run`)
    const sev = res.data?.report?.severity || 'none'
    if (sev === 'none') {
      ElMessage.success('Run complete — no drift detected')
    } else if (sev === 'info') {
      ElMessage.info('Run complete — minor change recorded')
    } else if (sev === 'warning') {
      ElMessage.warning('Drift detected — review the path')
    } else {
      ElMessage.error('Critical drift detected — immediate review needed')
    }
    invalidateTrend(m.id)
    await fetchAll()
    // If the trend panel is open for this monitor, eagerly refetch it.
    if (expandedId.value === m.id) {
      const [t, h] = await Promise.all([
        api.get(`/path-monitors/${m.id}/trend`),
        api.get(`/path-monitors/${m.id}/history`),
      ])
      trendData.value = { ...trendData.value, [m.id]: t.data }
      trendHistory.value = { ...trendHistory.value, [m.id]: h.data }
    }
  } catch (e) {
    ElMessage.error(
      e?.response?.data?.detail || e?.message || 'Run failed',
    )
  } finally {
    runningId.value = null
  }
}

async function toggleEnabled(m) {
  try {
    await api.put(`/path-monitors/${m.id}`, { enabled: !m.enabled })
    await fetchAll()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || 'Failed to update monitor')
  }
}

async function deleteMonitor(m) {
  try {
    await ElMessageBox.confirm(
      `Delete monitor for "${m.saved_query_name}"?`,
      'Delete monitor',
      { confirmButtonText: 'Delete', type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api.delete(`/path-monitors/${m.id}`)
    await fetchAll()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || 'Failed to delete')
  }
}

function formatTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleString()
}

function severityClass(sev) {
  if (sev === 'critical') return 'sev-critical'
  if (sev === 'warning')  return 'sev-warning'
  if (sev === 'info')     return 'sev-info'
  return ''
}

function severityTagType(sev) {
  if (sev === 'critical') return 'danger'
  if (sev === 'warning')  return 'warning'
  if (sev === 'info')     return 'info'
  return 'success'
}

function actionRequired(sev) {
  return sev === 'warning' || sev === 'critical'
}

// ── Outcome dialog ──────────────────────────────────────────────────────────
const outcomeOpen = ref(false)
const outcomeSaving = ref(false)
const outcomeTargetId = ref(null)
const outcomeForm = ref({
  outcome: null,
  root_cause_type: null,
  note: '',
})

function openOutcomeDialog(m) {
  outcomeTargetId.value = m.id
  outcomeForm.value = {
    outcome: null,
    root_cause_type: null,
    note: '',
  }
  outcomeOpen.value = true
}

async function submitOutcome() {
  const mid = outcomeTargetId.value
  if (!mid) return
  outcomeSaving.value = true
  try {
    const payload = { outcome: outcomeForm.value.outcome }
    if (outcomeForm.value.outcome === 'root_cause_identified') {
      payload.root_cause_type = outcomeForm.value.root_cause_type || 'unknown'
    }
    if (outcomeForm.value.note) payload.note = outcomeForm.value.note
    await api.post(`/path-monitors/${mid}/outcomes`, payload)
    outcomeOpen.value = false
    ElMessage.success('Outcome recorded')
    invalidateTrend(mid)
    await fetchAll()
  } catch (e) {
    ElMessage.error(
      e?.response?.data?.detail || e?.message || 'Failed to record outcome',
    )
  } finally {
    outcomeSaving.value = false
  }
}

// ── Noise control (mute / snooze / baseline / unsuppress) ───────────────────
const baselineOpen = ref(false)
const baselineSaving = ref(false)
const baselineTargetId = ref(null)
const baselineForm = ref({
  accepted_delay_max_ms: null,
  accepted_confidence_min: null,
  known_noisy_raw: '',
  known_gaps_raw: '',
})

async function handleNoiseControl(cmd, m) {
  if (cmd === 'mute') {
    try {
      await api.post(`/path-monitors/${m.id}/suppressions`, {
        kind: 'mute', reason: 'Manual mute',
      })
      ElMessage.success('Monitor muted')
      await fetchAll()
    } catch (e) {
      ElMessage.error(e?.response?.data?.detail || 'Failed to mute')
    }
  } else if (cmd === 'snooze') {
    const until = new Date(Date.now() + 24 * 3600 * 1000).toISOString()
    try {
      await api.post(`/path-monitors/${m.id}/suppressions`, {
        kind: 'snooze', reason: '24h snooze', until,
      })
      ElMessage.success('Snoozed for 24 hours')
      await fetchAll()
    } catch (e) {
      ElMessage.error(e?.response?.data?.detail || 'Failed to snooze')
    }
  } else if (cmd === 'baseline') {
    baselineTargetId.value = m.id
    try {
      const res = await api.get(`/path-monitors/${m.id}/baseline`)
      const b = res.data?.baseline || {}
      baselineForm.value = {
        accepted_delay_max_ms: b.accepted_delay_max_ms ?? null,
        accepted_confidence_min: b.accepted_confidence_min ?? null,
        known_noisy_raw: (b.known_noisy_impairments || []).join(', '),
        known_gaps_raw: (b.known_visibility_gaps || []).join('\n'),
      }
    } catch {
      baselineForm.value = {
        accepted_delay_max_ms: null, accepted_confidence_min: null,
        known_noisy_raw: '', known_gaps_raw: '',
      }
    }
    baselineOpen.value = true
  } else if (cmd === 'unsuppress') {
    try {
      const rules = await api.get(`/path-monitors/${m.id}/suppressions`)
      for (const r of rules.data || []) {
        await api.delete(`/path-monitors/${m.id}/suppressions/${r.id}`)
      }
      ElMessage.success('All suppressions removed')
      await fetchAll()
    } catch (e) {
      ElMessage.error(e?.response?.data?.detail || 'Failed to remove')
    }
  }
}

async function saveBaseline() {
  const mid = baselineTargetId.value
  if (!mid) return
  baselineSaving.value = true
  try {
    const payload = {}
    if (baselineForm.value.accepted_delay_max_ms != null) {
      payload.accepted_delay_max_ms = baselineForm.value.accepted_delay_max_ms
    }
    if (baselineForm.value.accepted_confidence_min != null) {
      payload.accepted_confidence_min = baselineForm.value.accepted_confidence_min
    }
    const noisy = baselineForm.value.known_noisy_raw
      .split(',').map(s => s.trim()).filter(Boolean)
    if (noisy.length) payload.known_noisy_impairments = noisy
    const gaps = baselineForm.value.known_gaps_raw
      .split('\n').map(s => s.trim()).filter(Boolean)
    if (gaps.length) payload.known_visibility_gaps = gaps
    await api.put(`/path-monitors/${mid}/baseline`, payload)
    baselineOpen.value = false
    ElMessage.success('Baseline saved')
    await fetchAll()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || 'Failed to save baseline')
  } finally {
    baselineSaving.value = false
  }
}

async function clearBaseline() {
  const mid = baselineTargetId.value
  if (!mid) return
  baselineSaving.value = true
  try {
    await api.put(`/path-monitors/${mid}/baseline`, {})
    baselineOpen.value = false
    ElMessage.success('Baseline cleared')
    await fetchAll()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || 'Failed to clear baseline')
  } finally {
    baselineSaving.value = false
  }
}

function outcomeLabel(oc) {
  if (oc === 'issue_confirmed') return 'Issue confirmed'
  if (oc === 'false_positive') return 'False positive'
  if (oc === 'transient_issue') return 'Transient'
  if (oc === 'root_cause_identified') return 'Root cause found'
  return oc
}

async function toggleTrend(m) {
  if (expandedId.value === m.id) {
    expandedId.value = null
    return
  }
  expandedId.value = m.id
  // Lazy-load: only fetch the first time the panel is opened
  if (!trendData.value[m.id]) {
    trendLoadingId.value = m.id
    try {
      const [t, h] = await Promise.all([
        api.get(`/path-monitors/${m.id}/trend`),
        api.get(`/path-monitors/${m.id}/history`),
      ])
      trendData.value = { ...trendData.value, [m.id]: t.data }
      trendHistory.value = { ...trendHistory.value, [m.id]: h.data }
    } catch (e) {
      ElMessage.error(
        e?.response?.data?.detail || e?.message || 'Failed to load trend',
      )
      expandedId.value = null
    } finally {
      trendLoadingId.value = null
    }
  }
}

// After a Run Now, drop the cached trend so the panel re-fetches next open.
function invalidateTrend(monitorId) {
  if (trendData.value[monitorId]) {
    const { [monitorId]: _t, ...rest } = trendData.value
    trendData.value = rest
  }
  if (trendHistory.value[monitorId]) {
    const { [monitorId]: _h, ...rest } = trendHistory.value
    trendHistory.value = rest
  }
}

function healthClass(score) {
  if (score >= 90) return 'health-good'
  if (score >= 70) return 'health-ok'
  if (score >= 40) return 'health-warn'
  return 'health-bad'
}

function slopeLabel(slope) {
  if (slope === 'worsening') return '↑ worsening'
  if (slope === 'improving') return '↓ improving'
  return '→ stable'
}

// For confidence, "worsening" should look bad even though the metric is going
// down; for backend delay, "worsening" means the value is going up. The colour
// logic doesn't actually depend on which one — but the boolean flag lets us
// keep the call sites unambiguous.
function slopeClass(slope, _isConfidence) {
  if (slope === 'worsening') return 'slope-bad'
  if (slope === 'improving') return 'slope-good'
  return 'slope-stable'
}

function barWidth(count) {
  if (!insights.value || !insights.value.monitor_count) return '0%'
  return Math.round((count / insights.value.monitor_count) * 100) + '%'
}

onMounted(fetchAll)
</script>

<style scoped>
.monitoring {
  max-width: 1100px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 20px;
}
.page-header h2 {
  font-size: 24px;
  font-weight: 700;
  color: #1a1a2e;
  margin-bottom: 6px;
}
.page-header p {
  color: #909399;
  font-size: 14px;
  max-width: 640px;
}

.header-actions {
  display: flex;
  gap: 8px;
}

/* ── System intelligence panel ─────────────────────────────────────────── */
.insights-panel {
  background: white;
  border-radius: 10px;
  border: 1px solid #e4e7ed;
  margin-bottom: 16px;
  overflow: hidden;
}
.insights-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 18px;
  cursor: pointer;
  user-select: none;
  border-bottom: 1px solid #f0f2f5;
}
.insights-header:hover { background: #fafbfd; }
.insights-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 700;
  font-size: 14px;
  color: #1a1a2e;
}
.insights-mini {
  flex: 1;
  font-size: 12px;
  color: #909399;
}
.expand-icon {
  transition: transform 0.2s;
}
.expand-icon.rotated { transform: rotate(180deg); }
.insights-body { padding: 14px 18px; }

.insight-section { margin-bottom: 14px; }
.insight-bullets {
  margin: 0;
  padding-left: 20px;
  font-size: 13px;
  color: #303133;
  line-height: 1.7;
}

.insight-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 14px;
}
@media (max-width: 900px) {
  .insight-cards { grid-template-columns: 1fr; }
}
.insight-card {
  background: #fafbfd;
  border-radius: 8px;
  border: 1px solid #ebeef5;
  padding: 12px 14px;
}
.insight-card-title {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  color: #606266;
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  gap: 6px;
}

/* Risk bars */
.risk-bars { display: flex; flex-direction: column; gap: 6px; }
.risk-bar-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11px;
}
.bar-label {
  width: 52px;
  text-align: right;
  font-weight: 600;
  text-transform: uppercase;
}
.bar-label.bar-critical { color: #f56c6c; }
.bar-label.bar-high     { color: #e6a23c; }
.bar-label.bar-medium   { color: #409eff; }
.bar-label.bar-low      { color: #67c23a; }
.bar-track {
  flex: 1;
  height: 8px;
  background: #ebeef5;
  border-radius: 4px;
  overflow: hidden;
}
.bar-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s;
}
.bar-fill.bar-critical { background: #f56c6c; }
.bar-fill.bar-high     { background: #e6a23c; }
.bar-fill.bar-medium   { background: #409eff; }
.bar-fill.bar-low      { background: #67c23a; }
.bar-count {
  width: 20px;
  text-align: right;
  color: #606266;
  font-weight: 600;
}

/* Root cause */
.rc-dominant {
  font-size: 13px;
  color: #303133;
  margin-bottom: 6px;
}
.rc-dominant .rc-label {
  font-weight: 700;
  text-transform: capitalize;
}
.rc-empty {
  font-size: 12px;
  color: #909399;
}
.rc-dist {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 6px;
}
.rc-chip {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 10px;
  background: #ebeef5;
  color: #606266;
}

/* Signals */
.signal-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}
.signal-name {
  font-size: 12px;
  color: #303133;
  font-weight: 500;
}
.noisy-section {
  margin-top: 8px;
  font-size: 11px;
  color: #909399;
}
.noisy-label { font-weight: 600; margin-right: 4px; }
.signal-noisy {
  background: #fef0f0;
  padding: 2px 6px;
  border-radius: 4px;
  color: #f56c6c;
  margin-right: 6px;
}

/* Systemic */
.systemic-block {
  margin: 12px 0;
  padding: 10px 14px;
  background: #fef0f0;
  border-radius: 8px;
  border: 1px solid #f9d7d7;
}
.systemic-block .insight-card-title { color: #f56c6c; }
.systemic-row {
  font-size: 13px;
  color: #303133;
  margin-bottom: 6px;
}
.systemic-row code {
  background: #f4f6fa;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 12px;
}
.systemic-monitor {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-left: 8px;
}

/* Shared impairments */
.shared-block { margin: 8px 0; }
.shared-tag { margin: 0 6px 6px 0; }

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 60px 20px;
  background: white;
  border-radius: 10px;
  border: 1px solid #e4e7ed;
  color: #909399;
}
.empty-state.error { color: #f56c6c; }
.empty-state .hint { font-size: 13px; }

.monitor-list {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.monitor-card {
  background: white;
  border-radius: 10px;
  border: 1px solid #e4e7ed;
  padding: 0 20px 18px 20px;
  border-left: 4px solid #d3d6dc;
  overflow: hidden;
}
.monitor-card.sev-critical { border-left-color: #f56c6c; }
.monitor-card.sev-warning  { border-left-color: #e6a23c; }
.monitor-card.sev-info     { border-left-color: #409eff; }
/* Outline a critical-risk path with a soft red glow so it stands out
   even when the user is scrolling fast. */
.monitor-card.risk-critical {
  border: 1px solid #f56c6c;
  border-left-width: 4px;
  box-shadow: 0 0 0 3px rgba(245, 108, 108, 0.08);
}
.monitor-card.risk-high {
  border-left-color: #e6a23c;
}

.risk-strip {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0 10px 0;
  margin: 0 -20px 14px -20px;
  padding-left: 20px;
  padding-right: 20px;
  border-bottom: 1px solid #f0f2f5;
  background: #fafbfd;
  font-size: 12px;
}
.risk-strip.risk-low      { background: #f0f9eb; }
.risk-strip.risk-medium   { background: #ecf5ff; }
.risk-strip.risk-high     { background: #fdf6ec; }
.risk-strip.risk-critical { background: #fef0f0; }
.risk-strip .risk-label {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #303133;
}
.risk-strip .risk-label :deep(.el-icon) {
  color: #f56c6c;
  font-size: 16px;
}
.risk-strip .risk-drivers {
  color: #606266;
  font-style: italic;
  text-align: right;
  max-width: 60%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.top-risk-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 18px;
  border-radius: 10px;
  background: #fef0f0;
  border: 1px solid #f56c6c;
  margin-bottom: 16px;
}
.top-risk-banner.risk-high     { background: #fdf6ec; border-color: #e6a23c; }
.top-risk-banner.risk-medium   { background: #ecf5ff; border-color: #409eff; }
.top-risk-banner :deep(.el-icon) {
  color: #f56c6c;
  font-size: 24px;
  flex-shrink: 0;
}
.top-risk-banner.risk-high   :deep(.el-icon) { color: #e6a23c; }
.top-risk-banner.risk-medium :deep(.el-icon) { color: #409eff; }
.banner-title {
  font-size: 14px;
  color: #303133;
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.banner-score {
  font-weight: 700;
  color: #f56c6c;
}
.top-risk-banner.risk-high   .banner-score { color: #e6a23c; }
.top-risk-banner.risk-medium .banner-score { color: #409eff; }
.banner-sub {
  font-size: 12px;
  color: #606266;
  margin-top: 3px;
}

.ranking-hint {
  font-size: 12px;
  color: #909399;
  font-style: italic;
}

.list-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
  gap: 12px;
}
.filter-count {
  display: inline-block;
  margin-left: 4px;
  padding: 0 6px;
  border-radius: 8px;
  background: #ebeef5;
  color: #606266;
  font-size: 11px;
  font-weight: 600;
}

/* Action badge sits on the right side of the risk strip */
.risk-strip .action-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-left: 6px;
  font-weight: 700;
  letter-spacing: 0.3px;
}
.risk-strip .action-badge :deep(.el-icon) {
  color: white;
  font-size: 12px;
}

/* Cards demanding action get a soft accent so they stand out without
   competing with the critical-risk red glow. */
.monitor-card.is-actionable:not(.risk-critical) {
  border-left-color: #f56c6c;
}

/* Action recommendation block */
.action-block {
  margin: 0 0 14px 0;
  padding: 10px 14px;
  border-radius: 8px;
  background: #fef0f0;
  border-left: 3px solid #f56c6c;
}
.action-block.priority-high   { background: #fdf6ec; border-left-color: #e6a23c; }
.action-block.priority-medium { background: #ecf5ff; border-left-color: #409eff; }
.action-headline {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: #303133;
  flex-wrap: wrap;
}
.priority-pill {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.4px;
  padding: 2px 8px;
  border-radius: 10px;
  background: #f56c6c;
  color: white;
  flex-shrink: 0;
}
.priority-pill.priority-high     { background: #e6a23c; }
.priority-pill.priority-medium   { background: #409eff; }
.priority-pill.priority-critical { background: #f56c6c; }
.action-focus {
  margin: 6px 0 0 0;
  padding-left: 22px;
  font-size: 12px;
  color: #606266;
  line-height: 1.6;
}

.card-head {
  display: flex;
  justify-content: space-between;
  gap: 12px;
}
.card-head h3 {
  font-size: 16px;
  font-weight: 700;
  color: #1a1a2e;
  margin: 0 0 4px 0;
}
.path-line {
  font-size: 13px;
  color: #606266;
  display: flex;
  align-items: center;
  gap: 6px;
}
.path-line code {
  background: #f4f6fa;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 12px;
}
.path-line .arrow { color: #909399; }
.sub-line {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
}
.card-head-right { flex-shrink: 0; }

.card-meta {
  display: flex;
  gap: 24px;
  margin-top: 12px;
  font-size: 12px;
}
.meta-label {
  color: #909399;
  margin-right: 6px;
}
.meta-value { color: #606266; font-weight: 500; }

.change-block {
  margin-top: 14px;
  padding: 12px 14px;
  background: #fafbfd;
  border-radius: 8px;
  border: 1px solid #ebeef5;
}
.change-title {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  color: #606266;
  margin-bottom: 6px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.severity-pill {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 10px;
  background: #e4e7ed;
  color: #606266;
}
.severity-pill.sev-critical { background: #fde2e2; color: #f56c6c; }
.severity-pill.sev-warning  { background: #faecd8; color: #e6a23c; }
.severity-pill.sev-info     { background: #d9ecff; color: #409eff; }
.change-block ul {
  margin: 0;
  padding-left: 18px;
  color: #303133;
  font-size: 13px;
  line-height: 1.6;
}
.action-required {
  margin-top: 8px;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #e6a23c;
}

.card-actions {
  display: flex;
  gap: 8px;
  margin-top: 14px;
  flex-wrap: wrap;
}

.suppressed-badge {
  background: #909399 !important;
  color: white !important;
  border: none !important;
}

.baseline-hint {
  font-size: 13px;
  color: #909399;
  margin: 0 0 12px 0;
}

.run-count {
  color: #909399;
  font-size: 11px;
  margin-left: 4px;
}

/* Outcome meta */
.outcome-tag {
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 11px;
}
.outcome-tag.oc-issue_confirmed      { background: #fef0f0; color: #f56c6c; }
.outcome-tag.oc-false_positive       { background: #f0f9eb; color: #67c23a; }
.outcome-tag.oc-transient_issue      { background: #ecf5ff; color: #409eff; }
.outcome-tag.oc-root_cause_identified { background: #fdf6ec; color: #e6a23c; }

.outcome-hints {
  margin: 8px 0;
  padding: 10px 14px;
  background: #f5f3ff;
  border-radius: 8px;
  border: 1px solid #e8e1f7;
}
.outcome-hints .trend-section-title {
  color: #7c5caf;
}
.outcome-hints ul {
  margin: 4px 0 0 0;
  padding-left: 18px;
  font-size: 12px;
  color: #606266;
  line-height: 1.6;
}

/* Trend panel */
.trend-panel {
  margin-top: 14px;
  padding: 14px 16px;
  background: #fafbfd;
  border-radius: 8px;
  border: 1px solid #ebeef5;
}
.trend-loading,
.trend-empty {
  color: #909399;
  font-size: 13px;
  text-align: center;
  padding: 12px;
}
.trend-section-title {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  color: #606266;
  margin: 12px 0 6px 0;
  display: flex;
  align-items: center;
  gap: 8px;
}

.trend-metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 8px;
}
.metric {
  background: white;
  border-radius: 6px;
  padding: 10px 12px;
  border: 1px solid #ebeef5;
}
.metric-label {
  font-size: 11px;
  color: #909399;
  text-transform: uppercase;
}
.metric-value {
  font-size: 22px;
  font-weight: 700;
  color: #1a1a2e;
}
.metric-value small {
  font-size: 12px;
  color: #909399;
  font-weight: 400;
}
.metric-value.health-good { color: #67c23a; }
.metric-value.health-ok   { color: #e6a23c; }
.metric-value.health-warn { color: #e6a23c; }
.metric-value.health-bad  { color: #f56c6c; }

.worsening-callout {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  background: #fdf2e9;
  border-left: 3px solid #e6a23c;
  padding: 10px 12px;
  border-radius: 4px;
  margin: 12px 0;
  color: #5a4a25;
  font-size: 13px;
}
.worsening-callout ul {
  margin: 4px 0 0 0;
  padding-left: 18px;
}
.worsening-callout :deep(.el-icon) {
  color: #e6a23c;
  font-size: 18px;
  margin-top: 1px;
}

.recurring-block { margin: 8px 0; }
.recurring-tag { margin: 0 6px 6px 0; }

.trend-lines {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin: 8px 0;
}
.trend-line {
  background: white;
  border-radius: 6px;
  padding: 10px 12px;
  border: 1px solid #ebeef5;
}
.trend-numbers {
  font-size: 12px;
  color: #606266;
  margin-bottom: 6px;
}
.slope {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 10px;
  background: #ebeef5;
  color: #606266;
}
.slope.slope-bad     { background: #fde2e2; color: #f56c6c; }
.slope.slope-good    { background: #e1f3d8; color: #67c23a; }
.slope.slope-stable  { background: #ebeef5; color: #606266; }

.sparkline { display: block; max-width: 100%; }
.sparkline-empty {
  font-size: 11px;
  color: #c0c4cc;
  padding: 6px 0;
}

.drift-timeline { margin: 12px 0; }
.timeline-row {
  display: flex;
  gap: 2px;
  flex-wrap: wrap;
}
.timeline-cell {
  width: 12px;
  height: 16px;
  border-radius: 2px;
  background: #ebeef5;
}
.timeline-cell.sev-none     { background: #67c23a; opacity: 0.55; }
.timeline-cell.sev-info     { background: #409eff; }
.timeline-cell.sev-warning  { background: #e6a23c; }
.timeline-cell.sev-critical { background: #f56c6c; }
.timeline-legend {
  display: flex;
  gap: 12px;
  font-size: 11px;
  color: #909399;
  margin-top: 6px;
}
.timeline-legend .legend {
  display: flex;
  align-items: center;
  gap: 4px;
}
.timeline-legend .dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
}
.timeline-legend .dot.sev-none     { background: #67c23a; opacity: 0.55; }
.timeline-legend .dot.sev-info     { background: #409eff; }
.timeline-legend .dot.sev-warning  { background: #e6a23c; }
.timeline-legend .dot.sev-critical { background: #f56c6c; }

.recent-runs { margin-top: 8px; }
.recent-runs table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  background: white;
  border-radius: 6px;
  overflow: hidden;
  border: 1px solid #ebeef5;
}
.recent-runs th,
.recent-runs td {
  text-align: left;
  padding: 6px 10px;
  border-bottom: 1px solid #f4f6fa;
}
.recent-runs th {
  background: #fafbfd;
  font-weight: 600;
  color: #606266;
}
.recent-runs tr:last-child td {
  border-bottom: none;
}

@media (max-width: 720px) {
  .trend-metrics { grid-template-columns: repeat(2, 1fr); }
  .trend-lines   { grid-template-columns: 1fr; }
}

.spinning {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}
</style>
