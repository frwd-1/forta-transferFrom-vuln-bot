import {
  Finding,
  FindingSeverity,
  FindingType,
  HandleTransaction,
  TransactionEvent,
} from "forta-agent";

export const ERC20_TRANSFERFROM_SIGNATURE =
  "event transferFrom(address from, address to, uint256 amount)";

let findingsCount = 0;

const handleTransaction: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  const findings: Finding[] = [];

  const transferFromCalls = txEvent.filterLog(ERC20_TRANSFERFROM_SIGNATURE);
  console.log("transferFromCalls:", transferFromCalls);

  transferFromCalls.forEach((call) => {
    const fromAddressNormalized = call.args.from
      ? call.args.from.toLowerCase()
      : "N/A";
    const txSenderNormalized = txEvent.from
      ? txEvent.from.toLowerCase()
      : "N/A";
    const toAddressNormalized = txEvent.to ? txEvent.to.toLowerCase() : "N/A";

    console.log("Detected transferFrom call");
    console.log("Message Sender:", txSenderNormalized);
    console.log("From parameter:", fromAddressNormalized);

    if (
      txSenderNormalized !== fromAddressNormalized &&
      txSenderNormalized !== "N/A" &&
      fromAddressNormalized !== "N/A"
    ) {
      findings.push(
        Finding.fromObject({
          name: "Suspicious transferFrom Call",
          description: `transferFrom called by different msg.sender: ${txSenderNormalized}`,
          alertId: "FORTA-2",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            from: fromAddressNormalized,
            messageSender: txSenderNormalized,
            interactedWith: toAddressNormalized,
          },
        })
      );
      findingsCount++;
    }
  });

  return findings;
};

export default {
  handleTransaction,
};
