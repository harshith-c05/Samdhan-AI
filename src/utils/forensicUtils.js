// Utility functions for forensics rendering

export function truncateHash(hash, length = 12) {
  if (!hash) return "N/A";
  if (hash.length <= length * 2) return hash;
  return `${hash.slice(0, length)}...${hash.slice(-length)}`;
}

export function formatBytes(bytes, decimals = 1) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

export function getTierBadgeClass(tier) {
  switch (tier?.toLowerCase()) {
    case 'critical':
      return 'bg-red-500/15 text-red-400 border border-red-500/40 shadow-[0_0_10px_rgba(239,68,68,0.2)]';
    case 'high':
      return 'bg-orange-500/15 text-orange-400 border border-orange-500/40 shadow-[0_0_10px_rgba(249,115,22,0.2)]';
    case 'medium':
      return 'bg-amber-500/15 text-amber-300 border border-amber-500/40';
    case 'low':
      return 'bg-zinc-700/30 text-zinc-400 border border-zinc-600/40';
    default:
      return 'bg-zinc-800 text-zinc-300 border border-zinc-700';
  }
}

export function getConfidenceBadgeClass(confidence) {
  // Confidence gets its own badge distinct from priority tier
  if (confidence >= 95) {
    return 'bg-cyber-500/15 text-cyber-neon border border-cyber-500/30';
  } else if (confidence >= 80) {
    return 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30';
  } else if (confidence >= 65) {
    return 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30';
  } else {
    return 'bg-purple-500/15 text-purple-300 border border-purple-500/30';
  }
}

export function getTypeIconName(type) {
  switch (type?.toLowerCase()) {
    case 'document':
      return 'FileText';
    case 'db log':
      return 'Database';
    case 'photo':
    case 'photos':
      return 'Image';
    case 'system trace':
      return 'Terminal';
    default:
      return 'Binary';
  }
}
